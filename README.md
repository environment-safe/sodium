@environment-safe/sodium
============================
This library is an ESM polyfill of [sodium-universal](https://www.npmjs.com/package/sodium-universal) along with ported tests from [chloride-tests](https://www.npmjs.com/package/chloride-test) and [sodium-javascript](https://www.npmjs.com/package/sodium-javascript) to native buildless ESM, usable in node or the browser, locally shimmed from the browserify compile ready to run in place, with no build needed.

Usage
-----

For docs consult the [sodium-native docs](https://sodium-friends.github.io/docs/docs/compatibility) and additionally pull in the `CryptoBuffer` definition for cross environment buffer handling.

```js
import { 
    CryptoBuffer, randombytes_buf
} from '@environment-safe/sodium';
var rnd = CryptoBuffer.allocUnsafe(12);
randombytes_buf(rnd);
// rnd now contains random data
```

Testing
-------

Run the es module tests to test the root modules
```bash
npm run import-test
```
to run the same test inside the browser:

```bash
npm run browser-test
```
to run the same test headless in chrome:
```bash
npm run headless-browser-test
```

to run the same test inside docker:
```bash
npm run container-test
```

Run the commonjs tests against the `/dist` commonjs source (generated with the `build-commonjs` target).
```bash
npm run require-test
```

Development
-----------
All work is done in the .mjs files and will be transpiled on commit to commonjs and tested.

If the above tests pass, then attempt a commit which will generate .d.ts files alongside the `src` files and commonjs classes in `dist`

