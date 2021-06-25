use super::Error;
use ring::io::der;

/// An ASN.1 timestamp.
#[derive(Copy, Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct ASN1Time(i64);

impl From<ASN1Time> for i64 {
    fn from(s: ASN1Time) -> i64 { s.0 }
}

#[cfg(feature = "std")]
impl ASN1Time {
    /// Gets the current time as an ASN1Time.
    ///
    /// Returns `Err` if the system clock is too far in the future to represent
    /// as an ASN.1 time, or if it is too far before this library was
    /// written.
    pub fn now() -> Result<Self, Error> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::BadDerTime)?
            .as_secs();
        if 1588297438 >= now || now > MAX_ASN1_TIMESTAMP as u64 {
            Err(Error::BadDerTime)
        } else {
            Ok(Self(now as i64))
        }
    }
}

impl core::convert::TryFrom<i64> for ASN1Time {
    type Error = Error;
    fn try_from(s: i64) -> Result<Self, Error> {
        if MIN_ASN1_TIMESTAMP <= s && s <= MAX_ASN1_TIMESTAMP {
            Ok(Self(s))
        } else {
            Err(Error::BadDerTime)
        }
    }
}

/// The largest timestamp that an ASN.1 GeneralizedTime can represent.
pub const MAX_ASN1_TIMESTAMP: i64 = 253_402_300_799;

/// The smallest timestamp that an ASN.1 GeneralizedTime can represent.
pub const MIN_ASN1_TIMESTAMP: i64 = -62_167_219_200;

macro_rules! convert_integers {
    ($($i: ident),*) => {
        $(let $i: u8 = $i.wrapping_sub(b'0'); { if $i > 9 { return Err( Error::BadDerTime) } })*
    }
}

macro_rules! collect {
    ($a: ident, $b: ident, $c: ident, $d: ident) => {{
        convert_integers!($a, $b, $c, $d);
        ((u16::from($a) * 10 + u16::from($b)) * 10 + u16::from($c)) * 10 + u16::from($d)
    }};
    ($a: ident, $b: ident) => {{
        convert_integers!($a, $b);
        10 * $a + $b
    }};
}

const UTC_TIME: u8 = der::Tag::UTCTime as _;
const GENERALIZED_TIME: u8 = der::Tag::GeneralizedTime as _;

pub(super) fn read_time(reader: &mut untrusted::Reader<'_>) -> Result<ASN1Time, Error> {
    let (tag, value) = der::read_tag_and_get_value(reader).map_err(|_| Error::BadDer)?;
    let (slice, month, day, hour, minute, second) = match *value.as_slice_less_safe() {
        [ref slice @ .., month1, month2, d1, d2, h1, h2, m1, m2, s1, s2, b'Z'] => {
            let month: u8 = collect!(month1, month2);
            let day: u8 = collect!(d1, d2);
            let hour: u8 = collect!(h1, h2);
            let minute: u8 = collect!(m1, m2);
            let second: u8 = collect!(s1, s2);
            (slice, month, day, hour, minute, second)
        },
        _ => return Err(Error::BadDerTime),
    };

    let year = match (tag, slice) {
        (UTC_TIME, &[y1, y2]) => {
            let year = collect!(y1, y2);
            (if year > 49 { 1900 } else { 2000u16 }) + u16::from(year)
        },
        (GENERALIZED_TIME, &[y1, y2, y3, y4]) => collect!(y1, y2, y3, y4),
        _ => return Err(Error::BadDer),
    };
    Ok(ASN1Time(
        86400 * i64::from(days_from_ymd(year, month, day)?)
            + i64::from(seconds_from_hms(hour, minute, second)?),
    ))
}

/// Convert an (hour, minute, second) tuple to a number of seconds since
/// midnight or an error.
pub fn seconds_from_hms(hour: u8, minute: u8, second: u8) -> Result<u32, Error> {
    if hour > 23 || minute > 59 || second > 59 {
        Err(Error::BadDerTime)
    } else {
        Ok((u32::from(hour) * 60 + u32::from(minute)) * 60 + u32::from(second))
    }
}

/// We use our own version, instead of chrono, because:
///
/// * We can (and do) perform exhaustive testing of every possible input. The
///   only possible inputs are (0, 0, 0) to (9999, 99, 99) inclusive, and we can
///   (and do) test every single one of them in a reasonable amount of time.
/// * It avoids an unnecessary dependency, and thus prevents bloat.
pub fn days_from_ymd(year: u16, month: u8, day: u8) -> Result<i32, Error> {
    const DAYS_IN_MONTH: [u8; 12] = [31, 0, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&month) || day < 1 {
        return Err(Error::BadDerTime);
    }
    if if month == 2 {
        let not_leap = year % 4 != 0 || (year % 100 == 0 && year % 400 != 0);
        day > 29u8 - u8::from(not_leap)
    } else {
        day > DAYS_IN_MONTH[month as usize - 1]
    } {
        return Err(Error::BadDerTime);
    }

    // Taken from https://howardhinnant.github.io/date_algorithms.html
    // Public domain
    let year: i32 = i32::from(year) - i32::from(month <= 2);
    let era: i32 = if year >= 0 { year } else { year - 399 } / 400;
    let yoe: i32 = year - era * 400;
    let months_since_feb = if month > 2 { month - 3 } else { month + 9 };
    // This is magic, but the unit-tests prove that it is correct.
    let doy: i32 = (153 * months_since_feb as i32 + 2) / 5 + i32::from(day) - 1;
    let doe: i32 = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok(era * 146097 + doe - 719468)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{offset::LocalResult, prelude::*};

    #[test]
    fn seconds_from_hms_works() {
        let mut last_second = u32::max_value();
        let date = Utc.ymd(1970, 1, 1);
        for hour in 0..100 {
            for minute in 0..100 {
                for second in 0..100 {
                    let seconds_since_midnight = seconds_from_hms(hour, minute, second);
                    if hour >= 24 || minute >= 60 || second >= 60 {
                        assert!(seconds_since_midnight.is_err());
                        assert!(date
                            .and_hms_opt(hour.into(), minute.into(), second.into())
                            .is_none());
                        continue;
                    }
                    let seconds_since_midnight = seconds_since_midnight.unwrap();
                    let chronos_version = date.and_hms(hour.into(), minute.into(), second.into());
                    assert_eq!(
                        chronos_version.timestamp(),
                        i64::from(seconds_since_midnight)
                    );
                    assert_eq!(last_second.wrapping_add(1), seconds_since_midnight);
                    assert!(seconds_since_midnight < 86400);
                    last_second = seconds_since_midnight;
                }
            }
        }
    }

    #[test]
    fn days_from_ymd_works() {
        let mut last_day = -719529i32;
        for year in 0u16..10000 {
            for month in 0u8..100 {
                for day in 0u8..100 {
                    let days_since_epoch = days_from_ymd(year, month, day);
                    match Utc.ymd_opt(year.into(), month.into(), day.into()) {
                        LocalResult::None => assert!(days_since_epoch.is_err()),
                        LocalResult::Single(e) => {
                            let this_day = days_since_epoch.unwrap();
                            assert_eq!(this_day, last_day.wrapping_add(1));
                            assert!(this_day < i32::max_value());
                            last_day = this_day;
                            assert_eq!(
                                e.and_hms(0, 0, 0).timestamp(),
                                i64::from(this_day) * 86400,
                                "mismatch for {:04}-{:02}-{:02}",
                                year,
                                month,
                                day,
                            )
                        },
                        LocalResult::Ambiguous(_, _) => unreachable!(),
                    }
                }
            }
        }
    }

    macro_rules! input_test {
        ($b: expr, $cmp: expr) => {
            assert_eq!(
                untrusted::Input::from($b)
                    .read_all(Error::CertExpired, read_time)
                    .map(i64::from),
                $cmp
            )
        };
    }

    #[test]
    fn wrong_length_rejected() {
        let too_long_utc = untrusted::Input::from(b"\x17\x0f99991231235959Z")
            .read_all(Error::CertExpired, read_time);
        assert_eq!(too_long_utc, Err(Error::BadDer));
        let too_short_generalized = untrusted::Input::from(b"\x18\x0d991231235959Z")
            .read_all(Error::CertExpired, read_time);
        assert_eq!(too_short_generalized, Err(Error::BadDer));
        assert!(253402300799u64.leading_zeros() > 25);
        input_test!(b"\x18\x0f99991231235959Z", Ok(MAX_ASN1_TIMESTAMP));
        input_test!(b"\x18\x0f:9991231235959Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f9:991231235959Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f99:91231235959Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f999:1231235959Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f9999 331235959Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f99991 31235959Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f999912 1235959Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f9999123 235959Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f99991231 35959Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f999912312 5959Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f9999123123 959Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f99991231235 59Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f999912312359 9Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f9999123123595 Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f99991231235959 ", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f99991231245959Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f99991331235959Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f99990001235959Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f99990431235959Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f99990431235959Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f99990229235959Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0d960229235959Z", Err(Error::BadDer));
        input_test!(b"\x18\x0f19600229235959Z", Ok(-310435201));
        input_test!(b"\x17\x0d490229235959Z", Err(Error::BadDerTime));
        input_test!(b"\x17\x0d490228235959Z", Ok(2498169599));
        input_test!(b"\x17\x0d500228235959Z", Ok(-626054401));
        input_test!(b"\x18\x0f19960229235959Z", Ok(825638399));
        input_test!(b"\x18\x0f00000101000000Z", Ok(MIN_ASN1_TIMESTAMP));
        input_test!(b"\x17\x0d960229235959Z", Ok(825638399));
        input_test!(b"\x18\x0f99960229235959Z", Ok(253281254399));
        input_test!(b"\x18\x0e99960229235959Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x1099960229235959Z", Err(Error::BadDer));
        input_test!(b"\x18\xFF99960229235959Z", Err(Error::BadDer));
        input_test!(b"\x18\x0f99000229235959Z", Err(Error::BadDerTime));
        input_test!(b"\x18\x0f96000229235959Z", Ok(240784703999));
    }
}
