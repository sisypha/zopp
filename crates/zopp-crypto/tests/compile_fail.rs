#[test]
fn no_debug_types() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/no_debug.rs");
}
