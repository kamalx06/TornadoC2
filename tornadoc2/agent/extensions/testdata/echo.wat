(module
  (import "env" "host_out" (func $out (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 16) "ok")
  (func (export "run") (result i32)
    (drop (call $out (i32.const 16) (i32.const 2)))
    (i32.const 0)))
