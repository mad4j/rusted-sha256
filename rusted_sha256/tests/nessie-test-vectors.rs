use hex_literal::hex;
use rusted_sha256::Sha256;

/// Test vectors from NESSIE project
/// https://www.cosic.esat.kuleuven.be/nessie/testvectors/hash/sha/Sha-2-256.unverified.test-vectors


/// Generate test data for Set 4 test cases
fn test_data(n: usize) -> [u8; 64] {
    let mut v = [0u8; 64];
    v[n / 8] = 0x80 >> (n % 8);
    return v;
}

// Set 1, vector#  0:
//                        message="" (empty string)
//                           hash=E3B0C44298FC1C149AFBF4C8996FB924
//                                27AE41E4649B934CA495991B7852B855
#[test]
fn test_nessie_set1_vec0() {
    assert_eq!(
        Sha256::digest(b""), 
        hex!("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
    )
}

#[test]
fn test_nessie_set1_vec1() {
    assert_eq!(
        Sha256::digest(b"a"), 
        hex!("CA978112CA1BBDCAFAC231B39A23DC4DA786EFF8147C4E72B9807785AFEE48BB")
    )
}

#[test]
fn test_nessie_set1_vec2() {
    assert_eq!(
        Sha256::digest(b"abc"), 
        hex!("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")
    )
}

#[test]
fn test_nessie_set1_vec3() {
    assert_eq!(
        Sha256::digest(b"message digest"), 
        hex!("F7846F55CF23E14EEBEAB5B4E1550CAD5B509E3348FBC4EFA3A1413D393CB650")
    )
}

#[test]
fn test_nessie_set1_vec4() {
    assert_eq!(
        Sha256::digest(b"abcdefghijklmnopqrstuvwxyz"), 
        hex!("71C480DF93D6AE2F1EFAD1447C66C9525E316218CF51FC8D9ED832F2DAF18B73")
    )
}

#[test]
fn test_nessie_set1_vec5() {
    assert_eq!(
        Sha256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), 
        hex!("248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1")
    )
}

#[test]
fn test_nessie_set1_vec6() {
    assert_eq!(
        Sha256::digest(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), 
        hex!("DB4BFCBD4DA0CD85A60C3C37D3FBD8805C77F15FC6B1FDFE614EE0A7C8FDB4C0")
    )
}

#[test]
fn test_nessie_set1_vec7() {
    assert_eq!(
        Sha256::digest(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"), 
        hex!("F371BC4A311F2B009EEF952DD83CA80E2B60026C8E935592D0F9C308453C813E")
    )
}

#[test]
fn test_nessie_set1_vec8() {
    assert_eq!(
        Sha256::digest(&[b'a'; 1_000_000]), 
        hex!("CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0")
    )
}

#[test]
fn test_nessie_set2_vec0() {
    assert_eq!(
        Sha256::digest(&[0; 0]), 
        hex!("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
    )
}

#[test]
fn test_nessie_set2_vec8() {
    assert_eq!(
        Sha256::digest(&[0; 1]), 
        hex!("6E340B9CFFB37A989CA544E6BB780A2C78901D3FB33738768511A30617AFA01D")
    )
}

#[test]
fn test_nessie_set2_vec16() {
    assert_eq!(
        Sha256::digest(&[0; 2]), 
        hex!("96A296D224F285C67BEE93C30F8A309157F0DAA35DC5B87E410B78630A09CFC7")
    )
}

#[test]
fn test_nessie_set2_vec24() {
    assert_eq!(
        Sha256::digest(&[0; 3]), 
        hex!("709E80C88487A2411E1EE4DFB9F22A861492D20C4765150C0C794ABD70F8147C")
    )
}

#[test]
fn test_nessie_set2_vec32() {
    assert_eq!(
        Sha256::digest(&[0; 4]), 
        hex!("DF3F619804A92FDB4057192DC43DD748EA778ADC52BC498CE80524C014B81119")
    )
}

#[test]
fn test_nessie_set2_vec40() {
    assert_eq!(
        Sha256::digest(&[0; 5]), 
        hex!("8855508AADE16EC573D21E6A485DFD0A7624085C1A14B5ECDD6485DE0C6839A4")
    )
}

#[test]
fn test_nessie_set2_vec48() {
    assert_eq!(
        Sha256::digest(&[0; 6]), 
        hex!("B0F66ADC83641586656866813FD9DD0B8EBB63796075661BA45D1AA8089E1D44")
    )
}

#[test]
fn test_nessie_set2_vec56() {
    assert_eq!(
        Sha256::digest(&[0; 7]), 
        hex!("837885C8F8091AEAEB9EC3C3F85A6FF470A415E610B8BA3E49F9B33C9CF9D619")
    )
}

#[test]
fn test_nessie_set2_vec64() {
    assert_eq!(
        Sha256::digest(&[0; 8]), 
        hex!("AF5570F5A1810B7AF78CAF4BC70A660F0DF51E42BAF91D4DE5B2328DE0E83DFC")
    )
}

#[test]
fn test_nessie_set3_vec0() {
    assert_eq!(
        Sha256::digest(&test_data(0)),
        hex!("A9E8913B13864096B9EA592F9548C87654AAF8DF24E3437645FAC174D1036E1C")
    )
}

#[test]
fn test_nessie_set3_vec1() {
    assert_eq!(
        Sha256::digest(&test_data(1)),
        hex!("F315F3F6D33215F8777A7D5A4B809F433729D13A86FE6ADF3DA5C11137E18273")
    )
}

#[test]
fn test_nessie_set3_vec2() {
    assert_eq!(
        Sha256::digest(&test_data(2)),
        hex!("AE1F446791358EEB17DEBD264614CAEB7F72558C085C73BE0DDE284B4C63A957")
    )
}

#[test]
fn test_nessie_set3_vec3() {
    assert_eq!(
        Sha256::digest(&test_data(3)),
        hex!("94C41AF484FFF7964969E0BDD922F82DFF0F4BE87A60D0664CC9D1FFD3ACD650")
    )
}

#[test]
fn test_nessie_set4_vec0() {
    assert_eq!(
        Sha256::digest(&[0u8; 32]),
        hex!("66687AADF862BD776C8FC18B8E9F8E20089714856EE233B3902A591D0D5F2925")
    );

    let mut data = [0u8; 32];

    for _ in 0..100_000 {
        data = Sha256::digest(&data);
    }

    assert_eq!(
        data,
        hex!("B422BC9C0646A432433C2410991C95E2D89758E3B4F540ACA863389F28A11379")
    )
}
