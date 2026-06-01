> [!IMPORTANT]
> UTF-C is a hobby project for the simple compression of UTF-8 strings with non-ASCII characters.

> [!NOTE]
> This project is a completely original work and does not follow any standards or templates. Contributions and improvements are welcome.

> [!TIP]
> This project supports SSE2, AVX2, AVX512, NEON and RVV ([`RISCV-Vector-1.0`](https://lists.riscv.org/g/tech-vector-ext/attachment/691/0/riscv-v-spec-1.0.pdf)).
>
> To use SIMD, please define:
> - "UTFC_SIMD_128" for SSE2/NEON/RVV
> - "UTFC_SIMD_256" for AVX2/RVV
> - "UTFC_SIMD_512" for AVX512/RVV

Example:
```
value: "😂😊😑😔😭"
bytes: [F0 9F 98 82 F0 9F 98 8A F0 9F 98 91 F0 9F 98 94 F0 9F 98 AD]
                 ┌Prefix reducer
                 │┌──[24 bits]┬Second bit
          ┌[00000XXX][32 bits]┼Both bits together
          │       │├─[16 bits]┴First bit
          │       └┴Additional bytes & total bits of length
┌───┬───┬─┴─┬────┬─────────────────────────┐
│ ? │ ? │ 0 │ 20 │ F0 9F 98 82 8A 91 94 AD │
├───┴───┼───┴────┼[8 bytes]────────────────┘
└Major  ├Flags   ├"😂😊😑😔😭" (20 bytes)
   Minor┘  Length┘
```

## 🐳 Test
Create an image for our build-environment:
`docker build . -t utfc-buildenv`

Enter our build-environment:
`docker run --rm -it -v "${pwd}:/workspace" utfc-buildenv`

### Commands
Build and run tests:
`make run` or `make arm=1 run` or `make riscv=1 run`

Remove all build files:
`make clean`

Leave the build-environment:
`exit`
