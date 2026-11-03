//! 画面の TypeScript を、ビルドのときに JavaScript にする (Node は要らない)。
//! 型はここでは確かめない。CI の tsc が確かめる

use std::path::Path;
use std::{env, fs};

use oxc::allocator::Allocator;
use oxc::codegen::Codegen;
use oxc::diagnostics::Diagnostics;
use oxc::parser::Parser;
use oxc::semantic::SemanticBuilder;
use oxc::span::SourceType;
use oxc::transformer::{TransformOptions, Transformer};

const SCRIPTS: [(&str, &str); 1] = [("assets/home/token.ts", "token.js")];

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR");
    println!("cargo:rerun-if-changed=build.rs");
    for (source, output) in SCRIPTS {
        println!("cargo:rerun-if-changed={source}");
        let path = Path::new(source);
        let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("{source}: {e}"));
        let script = transpile(path, &text);
        fs::write(Path::new(&out_dir).join(output), script).expect("write the script");
    }
}

fn transpile(path: &Path, source: &str) -> String {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, SourceType::ts()).parse();
    check(path, &parsed.diagnostics);
    let mut program = parsed.program;
    let scoping = SemanticBuilder::new()
        .build(&program)
        .semantic
        .into_scoping();
    let transformed = Transformer::new(&allocator, path, &TransformOptions::default())
        .build_with_scoping(scoping, &mut program);
    check(path, &transformed.diagnostics);
    Codegen::new().build(&program).code
}

fn check(path: &Path, diagnostics: &Diagnostics) {
    let errors: Vec<_> = diagnostics.errors().collect();
    assert!(errors.is_empty(), "{}: {errors:?}", path.display());
}
