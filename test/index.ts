import { should } from '@paulmillr/jsbt/test.js';
import './acvp.test.ts';
import './basic.test.ts';
import './hybrid.test.ts';
import './threshold.test.ts';
// import './errors.test.ts';

should.runWhen(import.meta.url);
