(module
  (import "env" "host_out" (func $out (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "hello from wasm")
  (func (export "abi_version") (result i32) i32.const 1)
  (func (export "run") (result i32)
    i32.const 0 i32.const 15 call $out drop
    i32.const 0))
