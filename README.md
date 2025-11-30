> [!IMPORTANT]
> UTF-C is a hobby project for the simple compression of UTF-8 strings with non-ASCII characters. This project is not a standard!

> [!NOTE]
> This project is a completely original work and does not follow any standards or templates. Contributions and improvements are welcome.

> [!TIP]
> This project supports SSE2, AVX2, AVX512 and NEON.
>
> To use SIMD, please define:
> - "UTFC_SIMD_128" for SSE2/NEON
> - "UTFC_SIMD_256" for AVX2
> - "UTFC_SIMD_512" for AVX512

Example:
```
                            ┌Prefix reducer
                            │┌──[24 bits]┬Second bit
                     ┌[00000xxx][32 bits]┼Both bits together
                     │       │├─[16 bits]┴First bit
                     │       └┴Additional bytes & total bits of length
┌──────────┬───┬───┬─┴─┬────┬───────────────────────────────────────────┐
│ 55 38 43 │ ? │ ? │ 0 │ 24 │ D7 90 A0 99 20 90 95 94 91 20 90 95 AA 9A │
├──────────┼───┴───┼───┴────┼[14 bytes]─────────────────────────────────┘
└Magic     └Major  ├Flags   ├"אני אוהב אותך" (24 bytes)
              Minor┘  Length┘
```

## 🐳 Test
Create an image for our build-environment:
`docker build . -t utfc-buildenv`

Enter our build-environment:
`docker run --rm -it -v "${pwd}:/workspace" utfc-buildenv`

### Commands
Build and run tests:
`make run` or `make arm=1 run`

Remove all build files:
`make clean`

Leave the build-environment:
`exit`