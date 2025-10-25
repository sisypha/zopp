use zopp_crypto::{Dek, MasterKey};

fn main() {
    // Attempting to require Debug should fail to compile
    fn assert_debug<T: std::fmt::Debug>() {}
    assert_debug::<Dek>();
    assert_debug::<MasterKey>();
}
