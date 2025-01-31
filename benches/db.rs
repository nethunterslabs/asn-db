use asn_db::Db;
use criterion::*;
use std::fs::File;
use std::io::{BufReader, Read};

fn db_data() -> impl Read {
    BufReader::new(File::open("asn-db.dat").unwrap())
}

fn bench_load(c: &mut Criterion) {
    c.bench(
        "AnsDb",
        Benchmark::new("load", move |b| {
            b.iter_with_large_drop(|| Db::load(db_data()).unwrap())
        })
        .sample_size(10),
    );
}

fn bench_lookup_list(c: &mut Criterion) {
    let db = Db::load(db_data()).unwrap();
    let ips = [
        "41.233.24.141",
        "113.195.171.20",
        "130.0.28.163",
        "123.20.216.84",
        "156.194.216.131",
        "113.172.111.142",
        "187.16.55.40",
        "156.213.34.161",
        "41.46.68.74",
        "156.194.98.93",
        "171.242.31.212",
        "119.76.188.94",
        "45.160.173.207",
        "42.52.215.60",
        "177.53.136.227",
        "201.49.229.167",
        "156.204.216.91",
        "41.47.36.238",
        "138.118.235.129",
        "37.215.197.113",
        "95.65.2.67",
        "14.231.133.175",
        "138.97.95.105",
        "197.61.48.167",
        "171.237.203.1",
        "37.114.129.174",
        "113.172.18.9",
        "41.235.106.191",
        "178.120.145.204",
        "14.248.10.19",
        "201.71.37.120",
        "189.204.52.237",
        "143.255.152.82",
        "156.204.19.58",
        "81.168.91.66",
        "37.114.160.227",
        "130.0.30.95",
        "196.219.72.142",
        "183.89.215.113",
        "95.52.71.230",
        "185.224.100.43",
        "37.114.128.228",
        "197.50.25.133",
        "148.0.112.30",
        "27.66.71.115",
        "123.16.152.23",
        "138.118.235.230",
        "61.7.191.252",
        "123.21.78.203",
        "37.114.160.7",
        "222.254.7.179",
        "111.177.244.137",
        "14.162.239.7",
        "177.155.123.175",
        "123.16.149.201",
        "138.204.70.36",
        "41.233.242.240",
        "123.16.251.77",
        "14.163.190.8",
        "41.218.217.18",
        "95.180.227.169",
        "196.20.132.207",
        "113.178.47.102",
        "41.38.59.1",
        "213.81.178.57",
        "41.232.214.12",
        "37.214.209.178",
        "37.191.220.141",
        "37.114.186.178",
        "183.89.84.166",
        "102.163.23.42",
        "113.173.112.164",
        "115.84.92.213",
        "186.232.150.127",
        "31.163.139.14",
        "170.79.177.13",
        "156.223.237.107",
        "119.42.127.250",
        "113.172.228.153",
        "99.243.73.186",
        "103.123.50.205",
        "109.169.228.99",
        "152.0.120.56",
        "116.107.253.159",
        "190.3.198.133",
        "190.29.98.134",
        "113.195.169.218",
        "123.21.131.28",
        "37.114.137.171",
        "14.187.6.130",
        "41.218.207.37",
        "120.28.68.2",
        "113.22.240.42",
        "14.232.245.167",
        "41.57.11.196",
        "41.202.171.48",
        "178.121.129.168",
        "171.241.28.184",
        "216.183.222.218",
        "123.20.9.230",
    ];
    let ips_count = ips.len();
    let ips = ips.iter().map(|ip| ip.parse().unwrap()).collect::<Vec<_>>();

    c.bench(
        "AnsDb",
        Benchmark::new("lookup - list", move |b| {
            b.iter(|| {
                assert!(
                    ips.iter()
                        .map(|ip| db.lookup_ipv4(*ip).unwrap())
                        .map(|r| r.as_number)
                        .sum::<u32>()
                        > 0
                )
            })
        })
        .throughput(Throughput::Elements(ips_count as u32)),
    );
}

fn bench_lookup_random(c: &mut Criterion) {
    use rand::distributions::Standard;
    use rand::Rng;
    use std::net::Ipv4Addr;

    let db = Db::load(db_data()).unwrap();
    let ips_count = 10_000;
    let ips = rand::thread_rng()
        .sample_iter(&Standard)
        .take(ips_count)
        .map(|v: u32| Ipv4Addr::from(v))
        .collect::<Vec<_>>();

    c.bench(
        "AnsDb",
        Benchmark::new("lookup - random", move |b| {
            b.iter(|| {
                ips.iter()
                    .map(|ip| db.lookup_ipv4(*ip).map(|r| r.as_number).unwrap_or(0))
                    .sum::<u32>()
            })
        })
        .throughput(Throughput::Elements(ips_count as u32)),
    );
}

criterion_group!(benches, bench_lookup_list, bench_lookup_random, bench_load);
criterion_main!(benches);
