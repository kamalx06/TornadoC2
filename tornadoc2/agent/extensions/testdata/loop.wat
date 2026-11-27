(module
  (func (export "run") (result i32)
    (loop $l (br $l))
    (i32.const 0)))
