wasm-snip --snip-rust-panicking-code -o aleo_utils.wasm aleo_utils.wasm
wasm-opt aleo_utils.wasm -all -o aleo_utils.wasm -Os --strip-debug --strip-dwarf --dce
