## 🐳 Test
Create an image for our build-environment:
`docker build . -t utfc-buildenv`

Enter our build-environment:
`docker run --rm -it -v "${pwd}:/workspace" utfc-buildenv`

### Commands
Build and run tests:
`make run`

Remove all build files:
`make clean`

Leave the build-environment:
`exit`