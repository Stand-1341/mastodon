import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { cpus, platform, arch } from 'node:os';
import { writeFileSync, mkdirSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { generateBotKeys, sampleMessage, signMessage, verifyMessage } from './auth.mjs';
const out = process.argv[2] || 'results';
mkdirSync(out, { recursive: true });
const n = 200, warmup = 20;
const algorithms = [ ['ML-DSA-87', () => generateKeyPairSync('ml-dsa-87'), null],
  ['RSA-3072-PKCS1-v1_5-SHA256', () => generateKeyPairSync('rsa', { modulusLength: 3072 }), 'sha256'] ];
const raw = [], summary = [];
function measure(fn, count, meta) {
  const values = [];
  for (let i = 0; i < count; i++) { const t = performance.now(); fn(); const ms = performance.now() - t; values.push(ms); raw.push({ ...meta, trial: i + 1, ms }); }
  values.sort((a,b) => a-b);
  return { n: count, median_ms: (values[Math.floor((count-1)/2)] + values[Math.ceil((count-1)/2)])/2,
    p95_ms: values[Math.ceil(count * .95)-1], mean_ms: values.reduce((a,b)=>a+b,0)/count };
}
for (const [name, keygen, hash] of algorithms) {
  const keys = keygen();
  // Key generation is recorded separately and is not included in sign/verify timings.
  summary.push({ algorithm: name, operation: 'keygen', payload_bytes: 0, ...measure(keygen, 20, { algorithm: name, operation: 'keygen', payload_bytes: 0 }) });
  for (const size of [128, 1024, 10240]) {
    const payload = Buffer.alloc(size, 'a');
    const sig = sign(hash, payload, keys.privateKey);
    if (!verify(hash, payload, keys.publicKey, sig)) throw new Error('Sanity check failed');
    for (let i=0; i<warmup; i++) { sign(hash,payload,keys.privateKey); verify(hash,payload,keys.publicKey,sig); }
    for (const [op, fn] of [['sign', () => sign(hash,payload,keys.privateKey)], ['verify', () => { if (!verify(hash,payload,keys.publicKey,sig)) throw new Error('Verification failed'); }]]) {
      summary.push({ algorithm: name, operation: op, payload_bytes: size, signature_bytes: sig.length,
        public_key_spki_der_bytes: keys.publicKey.export({ type: 'spki', format: 'der' }).length,
        ...measure(fn,n,{ algorithm:name, operation:op, payload_bytes:size }) });
    }
  }
}
const keys=generateBotKeys(), message=sampleMessage(), e=signMessage(message,keys.privateKey);
const cases=[['original',x=>x,keys.publicKey,true],['changed_content',x=>{x.message.content+='!';return x},keys.publicKey,false],
  ['changed_identity',x=>{x.message.botId='attacker';return x},keys.publicKey,false],
  ['wrong_key',x=>x,generateBotKeys().publicKey,false],['changed_signature',x=>{const b=Buffer.from(x.signature,'base64');b[0]^=1;x.signature=b.toString('base64');return x},keys.publicKey,false]];
const correctness = cases.map(([name,change,key,expected]) => {
  let accepted=0; for(let i=0;i<n;i++) accepted+=Number(verifyMessage(change(structuredClone(e)),key,message.botId));
  return { case:name, trials:n, accepted, rejected:n-accepted, expected_accept:expected, passed: accepted === (expected ? n : 0) };
});
if (correctness.some(x=>!x.passed)) throw new Error('Correctness failure');
const report={ recorded_at:new Date().toISOString(), environment:{node:process.version,openssl:process.versions.openssl,platform:platform(),arch:arch(),cpu:cpus()[0].model},
  methodology:{trials:n,warmup,keygen_trials:20,payload:'repeated ASCII a, UTF-8 bytes; crypto operations only',order:'ML-DSA-87 then RSA; sizes ascending; sequential trials', limitations:'One host/process/run; synthetic payloads; no network, AI inference, Rails or Pi measurements; same valid signature reused in verification trials. Rejection trials reuse one envelope and test behavior, not statistical security.'},summary,correctness};
writeFileSync(`${out}/benchmark.json`,JSON.stringify(report,null,2));
writeFileSync(`${out}/raw-timings.csv`,'algorithm,operation,payload_bytes,trial,ms\n'+raw.map(x=>[x.algorithm,x.operation,x.payload_bytes,x.trial,x.ms].join(',')).join('\n')+'\n');
console.log(JSON.stringify(report,null,2));
