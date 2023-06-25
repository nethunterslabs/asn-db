/*!
`asn-db` is a Rust library that can load and index [ASN] database (`ip2asn-v4.tsv` file) from [IPtoASN] website.
Once loaded it can be used to lookup an IP address for matching [ASN] record that contains:

* network base IP address and mask (e.g. [ipnet::Ipv4Net](https://docs.rs/ipnet/2.3.0/ipnet/struct.Ipv4Net.html) value like `1.1.1.0/24`),
* assigned AS number (e.g. `13335`),
* owner country code (e.g. `US`),
* owner information (e.g. `CLOUDFLARENET - Cloudflare, Inc.`).

# Example

Load database from `ip2asn-v4.tsv` file and lookup `1.1.1.1` IP address.

```rust
use asn_db::Db;
use std::fs::File;
use std::io::BufReader;

let db = Db::form_tsv(BufReader::new(File::open("ip2asn-v4.tsv").unwrap())).unwrap();
let record = db.lookup("1.1.1.1".parse().unwrap()).unwrap();

println!("{:#?}", record);
println!("{:#?}", record.network());
```

This prints:

```noformat
Record {
    ip: 16843008,
    prefix_len: 24,
    as_number: 13335,
    country: "US",
    owner: "CLOUDFLARENET - Cloudflare, Inc."
}
1.1.1.0/24
```

# Usage

Use `Db::from_tsv(input)` to load database from `ip2asn-v4.tsv` data.
You can then use `db.store(output)` to store the binary encoded data index for fast loading with `Db::load(input)`.

Use `db.lookup(ip)` to lookup for matching record by an IP address.

[ASN]: https://en.wikipedia.org/wiki/Autonomous_system_%28Internet%29#Assignment
[IPtoASN]: https://iptoasn.com/
*/
use std::cmp::Ordering;
use std::error::Error;
use std::fmt;
use std::io;
use std::io::{Read, Write};
pub use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bincode::{deserialize_from, serialize_into};
use error_context::*;
use ipnet::Ipv4Subnets;
use ipnet::Ipv6Subnets;
pub use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

const DATABASE_DATA_TAG: &[u8; 4] = b"ASDB";
const DATABASE_DATA_VERSION: &[u8; 4] = b"bin1";

/// Autonomous System number record.
#[derive(Serialize, Deserialize, Debug, Clone, Eq)]
pub struct Recordv4 {
    /// Network base IP address (host byte order).
    pub ip: u32,
    /// Network mask prefix in number of bits, e.g. 24 for 255.255.255.0 mask.
    pub prefix_len: u8,
    /// Assigned AS number.
    pub as_number: u32,
    /// Country code of network owner.
    pub country: String,
    /// Network owner information.
    pub owner: String,
}

impl PartialEq for Recordv4 {
    fn eq(&self, other: &Recordv4) -> bool {
        self.ip == other.ip
    }
}

impl Ord for Recordv4 {
    fn cmp(&self, other: &Recordv4) -> Ordering {
        self.ip.cmp(&other.ip)
    }
}

impl PartialOrd for Recordv4 {
    fn partial_cmp(&self, other: &Recordv4) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Recordv4 {
    /// Gets `Ipv4Net` representation of the network address.
    pub fn network(&self) -> Ipv4Net {
        Ipv4Net::new(self.ip.into(), self.prefix_len).expect("bad network")
    }
}

/// Autonomous System number record.
#[derive(Serialize, Deserialize, Debug, Clone, Eq)]
pub struct Recordv6 {
    /// Network base IP address (host byte order).
    pub ip: u128,
    /// Network mask prefix in number of bits, e.g. 24 for 255.255.255.0 mask.
    pub prefix_len: u8,
    /// Assigned AS number.
    pub as_number: u32,
    /// Country code of network owner.
    pub country: String,
    /// Network owner information.
    pub owner: String,
}

impl PartialEq for Recordv6 {
    fn eq(&self, other: &Recordv6) -> bool {
        self.ip == other.ip
    }
}

impl Ord for Recordv6 {
    fn cmp(&self, other: &Recordv6) -> Ordering {
        self.ip.cmp(&other.ip)
    }
}

impl PartialOrd for Recordv6 {
    fn partial_cmp(&self, other: &Recordv6) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Recordv6 {
    /// Gets `Ipv4Net` representation of the network address.
    pub fn network(&self) -> Ipv6Net {
        Ipv6Net::new(self.ip.into(), self.prefix_len).expect("bad network")
    }
}

pub enum Record<'a> {
    V4(&'a Recordv4),
    V6(&'a Recordv6),
}

impl Record<'_> {
    /// Gets `IpNet` representation of the network address.
    pub fn network(&self) -> IpNet {
        match self {
            Record::V4(record) => IpNet::V4(record.network()),
            Record::V6(record) => IpNet::V6(record.network()),
        }
    }

    /// Gets `IpAddr` representation of the network address.
    pub fn ip(&self) -> IpAddr {
        match self {
            Record::V4(record) => IpAddr::V4(record.network().network()),
            Record::V6(record) => IpAddr::V6(record.network().network()),
        }
    }

    /// Gets network mask prefix in number of bits, e.g. 24 for
    pub fn prefix_len(&self) -> u8 {
        match self {
            Record::V4(record) => record.prefix_len,
            Record::V6(record) => record.prefix_len,
        }
    }

    /// Gets assigned AS number.
    pub fn as_number(&self) -> u32 {
        match self {
            Record::V4(record) => record.as_number,
            Record::V6(record) => record.as_number,
        }
    }

    /// Gets country code of network owner.
    pub fn country(&self) -> &str {
        match self {
            Record::V4(record) => &record.country,
            Record::V6(record) => &record.country,
        }
    }

    /// Gets network owner information.
    pub fn owner(&self) -> &str {
        match self {
            Record::V4(record) => &record.owner,
            Record::V6(record) => &record.owner,
        }
    }
}

#[derive(Debug)]
pub enum TsvParseError {
    TsvError(csv::Error),
    AddrFieldParseError(std::net::AddrParseError, &'static str),
    IntFieldParseError(std::num::ParseIntError, &'static str),
}

impl fmt::Display for TsvParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TsvParseError::TsvError(_) => write!(f, "TSV format error"),
            TsvParseError::AddrFieldParseError(_, context) => {
                write!(f, "error parsing IP address while {}", context)
            }
            TsvParseError::IntFieldParseError(_, context) => {
                write!(f, "error parsing integer while {}", context)
            }
        }
    }
}

impl Error for TsvParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            TsvParseError::TsvError(err) => Some(err),
            TsvParseError::AddrFieldParseError(err, _) => Some(err),
            TsvParseError::IntFieldParseError(err, _) => Some(err),
        }
    }
}

impl From<csv::Error> for TsvParseError {
    fn from(error: csv::Error) -> TsvParseError {
        TsvParseError::TsvError(error)
    }
}

impl From<ErrorContext<std::net::AddrParseError, &'static str>> for TsvParseError {
    fn from(ec: ErrorContext<std::net::AddrParseError, &'static str>) -> TsvParseError {
        TsvParseError::AddrFieldParseError(ec.error, ec.context)
    }
}

impl From<ErrorContext<std::num::ParseIntError, &'static str>> for TsvParseError {
    fn from(ec: ErrorContext<std::num::ParseIntError, &'static str>) -> TsvParseError {
        TsvParseError::IntFieldParseError(ec.error, ec.context)
    }
}

/// Reads ASN database TSV file (`ip2asn-v4.tsv` format) provided by [IPtoASN](https://iptoasn.com/) as iterator of `Record`s.
pub fn read_asn_v4_tsv<R: io::Read>(
    data: &mut csv::Reader<R>,
) -> impl Iterator<Item = Result<Recordv4, TsvParseError>> + '_ {
    data.records()
        .filter(|record| {
            if let Ok(record) = record {
                let owner = &record[4];
                !(owner == "Not routed" || owner == "None")
            } else {
                true
            }
        })
        .map(|record| record.map_err(Into::<TsvParseError>::into))
        .map(|record| {
            record.and_then(|record| {
                let range_start: Ipv4Addr = record[0]
                    .parse()
                    .wrap_error_while("parsing range_start IP")?;
                let range_end: Ipv4Addr =
                    record[1].parse().wrap_error_while("parsing range_end IP")?;
                let as_number: u32 = record[2].parse().wrap_error_while("parsing as_number")?;
                let country = record[3].to_owned();
                let owner = record[4].to_owned();
                Ok((range_start, range_end, as_number, country, owner))
            })
        })
        .map(|record| {
            record.map(|(range_start, range_end, as_number, country, owner)| {
                // Convert range into one or more subnets iterator
                Ipv4Subnets::new(range_start, range_end, 8).map(move |subnet| Recordv4 {
                    ip: subnet.network().into(),
                    prefix_len: subnet.prefix_len(),
                    country: country.clone(),
                    as_number,
                    owner: owner.clone(),
                })
            })
        })
        .flat_map(|subnet_records| {
            // Flatten many records or single error
            let mut records = None;
            let mut error = None;

            match subnet_records {
                Ok(subnet_records) => records = Some(subnet_records),
                Err(err) => error = Some(err),
            }

            records
                .into_iter()
                .flatten()
                .map(Ok)
                .chain(error.into_iter().map(Err))
        })
}

/// Reads ASN database TSV file (`ip2asn-v4.tsv` format) provided by [IPtoASN](https://iptoasn.com/) as iterator of `Record`s.
pub fn read_asn_v6_tsv<R: io::Read>(
    data: &mut csv::Reader<R>,
) -> impl Iterator<Item = Result<Recordv6, TsvParseError>> + '_ {
    data.records()
        .filter(|record| {
            if let Ok(record) = record {
                let owner = &record[4];
                !(owner == "Not routed" || owner == "None")
            } else {
                true
            }
        })
        .map(|record| record.map_err(Into::<TsvParseError>::into))
        .map(|record| {
            record.and_then(|record| {
                let range_start: Ipv6Addr = record[0]
                    .parse()
                    .wrap_error_while("parsing range_start IP")?;
                let range_end: Ipv6Addr =
                    record[1].parse().wrap_error_while("parsing range_end IP")?;
                let as_number: u32 = record[2].parse().wrap_error_while("parsing as_number")?;
                let country = record[3].to_owned();
                let owner = record[4].to_owned();
                Ok((range_start, range_end, as_number, country, owner))
            })
        })
        .map(|record| {
            record.map(|(range_start, range_end, as_number, country, owner)| {
                // Convert range into one or more subnets iterator
                Ipv6Subnets::new(range_start, range_end, 8).map(move |subnet| Recordv6 {
                    ip: subnet.network().into(),
                    prefix_len: subnet.prefix_len(),
                    country: country.clone(),
                    as_number,
                    owner: owner.clone(),
                })
            })
        })
        .flat_map(|subnet_records| {
            // Flatten many records or single error
            let mut records = None;
            let mut error = None;

            match subnet_records {
                Ok(subnet_records) => records = Some(subnet_records),
                Err(err) => error = Some(err),
            }

            records
                .into_iter()
                .flatten()
                .map(Ok)
                .chain(error.into_iter().map(Err))
        })
}

#[derive(Debug)]
pub enum DbError {
    TsvError(TsvParseError),
    DbDataError(&'static str),
    FileError(io::Error, &'static str),
    BincodeError(bincode::Error, &'static str),
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DbError::TsvError(_) => write!(f, "error opening ASN DB from TSV file"),
            DbError::FileError(_, context) => {
                write!(f, "error opening ASN DB from file while {}", context)
            }
            DbError::BincodeError(_, context) => write!(
                f,
                "error (de)serializing ASN DB to bincode format while {}",
                context
            ),
            DbError::DbDataError(message) => write!(f, "error while reading database: {}", message),
        }
    }
}

impl Error for DbError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DbError::TsvError(err) => Some(err),
            DbError::FileError(err, _) => Some(err),
            DbError::BincodeError(err, _) => Some(err),
            DbError::DbDataError(_) => None,
        }
    }
}

impl From<TsvParseError> for DbError {
    fn from(err: TsvParseError) -> DbError {
        DbError::TsvError(err)
    }
}

impl From<ErrorContext<io::Error, &'static str>> for DbError {
    fn from(err: ErrorContext<io::Error, &'static str>) -> DbError {
        DbError::FileError(err.error, err.context)
    }
}

impl From<ErrorContext<bincode::Error, &'static str>> for DbError {
    fn from(err: ErrorContext<bincode::Error, &'static str>) -> DbError {
        DbError::BincodeError(err.error, err.context)
    }
}

//TODO: Use eytzinger layout - requires non exact search support.
//TODO: Support for mmap'ed files to reduce memory usage?
//TODO: IPv6 support.
//TODO: Support providing all subnets of matched range.
/// ASN record database that is optimized for lookup by an IP address.
#[derive(Serialize, Deserialize)]
pub struct Db {
    ipv4_records: Vec<Recordv4>,
    ipv6_records: Vec<Recordv6>,
}

impl fmt::Debug for Db {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "asn_db::Db[total records: {}]",
            self.ipv4_records.len() + self.ipv6_records.len()
        )
    }
}

impl Db {
    /// Loads database from ASN data as provided by [IPtoASN](https://iptoasn.com/) - the only supported file format is of the `ip2asn-v4.tsv` and `ip2asn-v6.tsv` files.
    pub fn from_tsv(ipv4_tsv: impl Read, ipv6_tsv: impl Read) -> Result<Db, DbError> {
        let mut rdr = csv::ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(ipv4_tsv);
        let mut ipv4_records = read_asn_v4_tsv(&mut rdr).collect::<Result<Vec<_>, _>>()?;
        ipv4_records.sort();
        let mut rdr = csv::ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(ipv6_tsv);
        let mut ipv6_records = read_asn_v6_tsv(&mut rdr).collect::<Result<Vec<_>, _>>()?;
        ipv6_records.sort();
        Ok(Db {
            ipv4_records,
            ipv6_records,
        })
    }

    /// Loads database from the binary index that was stored with `.store()` - this method is much faster than loading from the TSV file.
    pub fn load(mut db_data: impl Read) -> Result<Db, DbError> {
        let mut tag = [0; 4];
        db_data
            .read_exact(&mut tag)
            .wrap_error_while("reading database tag")?;
        if &tag != DATABASE_DATA_TAG {
            return Err(DbError::DbDataError("bad database data tag"));
        }

        let mut version = [0; 4];
        db_data
            .read_exact(&mut version)
            .wrap_error_while("reading database version")?;
        if &version != DATABASE_DATA_VERSION {
            return Err(DbError::DbDataError("unsuported database version"));
        }

        let records: Db = deserialize_from(db_data).wrap_error_while("reading bincode DB file")?;

        Ok(records)
    }

    /// Stores database as a binary index for fast loading with `.load()`.
    pub fn store(&self, mut db_data: impl Write) -> Result<(), DbError> {
        db_data
            .write(DATABASE_DATA_TAG)
            .wrap_error_while("error writing tag")?;
        db_data
            .write(DATABASE_DATA_VERSION)
            .wrap_error_while("error writing version")?;
        serialize_into(db_data, &self).wrap_error_while("stroing DB")?;
        Ok(())
    }

    /// Performs lookup by an IP address for the ASN `Record` of which network this IP belongs to.
    pub fn lookup(&self, ip: IpAddr) -> Option<Record> {
        match ip {
            IpAddr::V4(ip) => self.lookup_ipv4(ip).map(Record::V4),
            IpAddr::V6(ip) => self.lookup_ipv6(ip).map(Record::V6),
        }
    }

    /// Performs lookup by an IPv4 address for the ASN `Record` of which network this IP belongs to.
    pub fn lookup_ipv4(&self, ip: Ipv4Addr) -> Option<&Recordv4> {
        match self
            .ipv4_records
            .binary_search_by_key(&ip.into(), |record| record.ip)
        {
            Ok(index) => return Some(&self.ipv4_records[index]), // IP was network base IP
            Err(index) => {
                // upper bound/insert index
                if index != 0 {
                    let record = &self.ipv4_records[index - 1];
                    if record.network().contains(&ip) {
                        return Some(record);
                    }
                }
            }
        }
        None
    }

    /// Performs lookup by an IPv6 address for the ASN `Record` of which network this IP belongs to.
    pub fn lookup_ipv6(&self, ip: Ipv6Addr) -> Option<&Recordv6> {
        match self
            .ipv6_records
            .binary_search_by_key(&ip.into(), |record| record.ip)
        {
            Ok(index) => return Some(&self.ipv6_records[index]), // IP was network base IP
            Err(index) => {
                // upper bound/insert index
                if index != 0 {
                    let record = &self.ipv6_records[index - 1];
                    if record.network().contains(&ip) {
                        return Some(record);
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{BufReader, BufWriter};
    use tempfile::tempdir;

    #[test]
    fn test_db() {
        let db = Db::from_tsv(
            BufReader::new(File::open("ip2asn-v4.tsv").unwrap()),
            BufReader::new(File::open("ip2asn-v6.tsv").unwrap()),
        )
        .unwrap();

        assert!(db
            .lookup_ipv4("1.1.1.0".parse().unwrap())
            .unwrap()
            .owner
            .contains("CLOUDFLARENET"));
        assert!(db
            .lookup_ipv4("1.1.1.1".parse().unwrap())
            .unwrap()
            .owner
            .contains("CLOUDFLARENET"));
        assert!(db
            .lookup_ipv4("1.1.1.2".parse().unwrap())
            .unwrap()
            .owner
            .contains("CLOUDFLARENET"));
        assert!(db
            .lookup_ipv4("8.8.8.8".parse().unwrap())
            .unwrap()
            .owner
            .contains("GOOGLE"));
        assert!(db
            .lookup_ipv4("8.8.4.4".parse().unwrap())
            .unwrap()
            .owner
            .contains("GOOGLE"));
        assert!(db
            .lookup_ipv6("2001:4860:4860::8888".parse().unwrap())
            .unwrap()
            .owner
            .contains("GOOGLE"));
        assert!(db
            .lookup_ipv6("2001:4860:4860::8844".parse().unwrap())
            .unwrap()
            .owner
            .contains("GOOGLE"));

        let temp_dir = tempdir().unwrap();
        let db_file = temp_dir.path().join("asn-db.dat");

        db.store(BufWriter::new(File::create(&db_file).unwrap()))
            .unwrap();

        let db = Db::load(BufReader::new(File::open(&db_file).unwrap())).unwrap();

        drop(db_file);
        drop(temp_dir);

        assert!(db
            .lookup_ipv4("1.1.1.0".parse().unwrap())
            .unwrap()
            .owner
            .contains("CLOUDFLARENET"));
        assert!(db
            .lookup_ipv4("1.1.1.1".parse().unwrap())
            .unwrap()
            .owner
            .contains("CLOUDFLARENET"));
        assert!(db
            .lookup_ipv4("1.1.1.2".parse().unwrap())
            .unwrap()
            .owner
            .contains("CLOUDFLARENET"));
        assert!(db
            .lookup_ipv4("8.8.8.8".parse().unwrap())
            .unwrap()
            .owner
            .contains("GOOGLE"));
        assert!(db
            .lookup_ipv4("8.8.4.4".parse().unwrap())
            .unwrap()
            .owner
            .contains("GOOGLE"));
        assert!(db
            .lookup_ipv6("2001:4860:4860::8888".parse().unwrap())
            .unwrap()
            .owner
            .contains("GOOGLE"));
        assert!(db
            .lookup_ipv6("2001:4860:4860::8844".parse().unwrap())
            .unwrap()
            .owner
            .contains("GOOGLE"));
    }
}
