[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)
![Build](https://github.com/bedlaj/sha512-crypt-ts/workflows/Build/badge.svg)
![Test and publish](https://github.com/bedlaj/sha512-crypt-ts/workflows/Test%20and%20publish/badge.svg)
[![codecov](https://codecov.io/gh/bedlaj/sha512-crypt-ts/branch/master/graph/badge.svg)](https://codecov.io/gh/bedlaj/sha512-crypt-ts)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/bedlaj/sha512-crypt-ts.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/bedlaj/sha512-crypt-ts/alerts/)
[![Language grade: JavaScript](https://img.shields.io/lgtm/grade/javascript/g/bedlaj/sha512-crypt-ts.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/bedlaj/sha512-crypt-ts/context:javascript)

# SHA-512-crypt-ts
Crypt compatible typescript implementation inspired by [mvo5/sha512crypt-node](https://github.com/mvo5/sha512crypt-node)

# Installation
#### Install [NPM package](https://www.npmjs.com/package/sha512-crypt-ts)
```
npm install --save sha512-crypt-ts
```
#### Import module
```
import { sha512 } from 'sha512-crypt-ts';
```
#### Usage
```
sha512.crypt('password', 'saltsalt');
// This is equivalent to: printf "password" | mkpasswd --stdin --method=sha-512 --salt=saltsalt
// Returns $6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/
```
Another examples can be found in [unit tests](https://github.com/bedlaj/sha512-crypt-ts/blob/master/tests/sha512.test.ts) or in peer project [bedlaj/unifi-reset-password](https://github.com/bedlaj/unifi-reset-password/blob/master/src/app/app.component.ts).

#### Documentation
Generated docs can be found at https://bedlaj.github.io/sha512-crypt-ts/modules/sha512.html
