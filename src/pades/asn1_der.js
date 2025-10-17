'use strict';
const DER = {
  len(n){ if(n<0x80) return Buffer.from([n]); const a=[]; let t=n; while(t>0){a.unshift(t&0xff); t>>=8;} return Buffer.from([0x80|a.length, ...a]); },
  tag(t,c){ return Buffer.concat([Buffer.from([t]), this.len(c.length), c]); },
  seq(...els){ return this.tag(0x30, Buffer.concat(els)); },
  set(...els){ const sorted=els.slice().sort(Buffer.compare); return this.tag(0x31, Buffer.concat(sorted)); },
  oid(oid){
    const parts=oid.split('.').map(n=>parseInt(n,10)); const first=40*parts[0]+parts[1];
    const out=[first];
    for(let i=2;i<parts.length;i++){ let v=parts[i], tmp=[v&0x7f]; v>>=7; while(v>0){ tmp.unshift((v&0x7f)|0x80); v>>=7; } out.push(...tmp); }
    return this.tag(0x06, Buffer.from(out));
  },
  null(){ return Buffer.from([0x05,0x00]); },
  octet(b){ return this.tag(0x04, Buffer.from(b)); },
  bitstr(b){ return this.tag(0x03, Buffer.concat([Buffer.from([0x00]), Buffer.from(b)])); },
  intFromBuf(b){ let x=Buffer.from(b); if(x.length===0) x=Buffer.from([0]); if(x[0]&0x80) x=Buffer.concat([Buffer.from([0x00]), x]); return this.tag(0x02, x); },
  algo(oid, withNull=true){ return this.seq(this.oid(oid), withNull? this.null(): Buffer.alloc(0)); },
  ctxExplicit(tagNo, der){ return this.tag(0xA0+tagNo, der); },
  retagImplicit(buf, newTag){ const out=Buffer.from(buf); out[0]=newTag; return out; },
  any(b){ return Buffer.from(b); }
};
module.exports = { DER };
