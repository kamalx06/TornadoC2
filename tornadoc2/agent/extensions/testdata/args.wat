(module
  (import "env" "host_args" (func $args (param i32 i32) (result i32)))
  (import "env" "host_out" (func $out (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "run") (result i32)
    (local $n i32)
    (local.set $n (call $args (i32.const 32) (i32.const 120)))
    (drop (call $out (i32.const 32) (local.get $n)))
    (i32.const 7)))
