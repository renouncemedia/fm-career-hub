
/* ============================================================
   FM SaveLens PT — parser do save FM24
   Porto adaptado (para browser) do parser original TypeScript
   do projeto open-source "FM SaveLens 24" (MSalman5230), que
   fez o reverse-engineering do formato binário do save do FM24.
   Licença original: ver repositório do projeto.
   Descompressão zstd: biblioteca "fzstd" (MIT, 101arrowz).
   ============================================================ */

/* ---------- fzstd (descompressor Zstandard em JS puro) ---------- */
const Zstd = (function () {
// Some numerical data is initialized as -1 even when it doesn't need initialization to help the JIT infer types
// aliases for shorter compressed code (most minifers don't do this)
var ab = ArrayBuffer, u8 = Uint8Array, u16 = Uint16Array, i16 = Int16Array, u32 = Uint32Array, i32 = Int32Array;
var slc = function (v, s, e) {
    if (u8.prototype.slice)
        return u8.prototype.slice.call(v, s, e);
    if (s == null || s < 0)
        s = 0;
    if (e == null || e > v.length)
        e = v.length;
    var n = new u8(e - s);
    n.set(v.subarray(s, e));
    return n;
};
var fill = function (v, n, s, e) {
    if (u8.prototype.fill)
        return u8.prototype.fill.call(v, n, s, e);
    if (s == null || s < 0)
        s = 0;
    if (e == null || e > v.length)
        e = v.length;
    for (; s < e; ++s)
        v[s] = n;
    return v;
};
var cpw = function (v, t, s, e) {
    if (u8.prototype.copyWithin)
        return u8.prototype.copyWithin.call(v, t, s, e);
    if (s == null || s < 0)
        s = 0;
    if (e == null || e > v.length)
        e = v.length;
    while (s < e) {
        v[t++] = v[s++];
    }
};
/**
 * Codes for errors generated within this library
 */
var ZstdErrorCode = {
    InvalidData: 0,
    WindowSizeTooLarge: 1,
    InvalidBlockType: 2,
    FSEAccuracyTooHigh: 3,
    DistanceTooFarBack: 4,
    UnexpectedEOF: 5
};
// error codes
var ec = [
    'invalid zstd data',
    'window size too large (>2046MB)',
    'invalid block type',
    'FSE accuracy too high',
    'match distance too far back',
    'unexpected EOF'
];
var err = function (ind, msg, nt) {
    var e = new Error(msg || ec[ind]);
    e.code = ind;
    if (Error.captureStackTrace)
        Error.captureStackTrace(e, err);
    if (!nt)
        throw e;
    return e;
};
var rb = function (d, b, n) {
    var i = 0, o = 0;
    for (; i < n; ++i)
        o |= d[b++] << (i << 3);
    return o;
};
var b4 = function (d, b) { return (d[b] | (d[b + 1] << 8) | (d[b + 2] << 16) | (d[b + 3] << 24)) >>> 0; };
// read Zstandard frame header
var rzfh = function (dat, w) {
    var n3 = dat[0] | (dat[1] << 8) | (dat[2] << 16);
    if (n3 == 0x2FB528 && dat[3] == 253) {
        // Zstandard
        var flg = dat[4];
        //    single segment       checksum             dict flag     frame content flag
        var ss = (flg >> 5) & 1, cc = (flg >> 2) & 1, df = flg & 3, fcf = flg >> 6;
        if (flg & 8)
            err(0);
        // byte
        var bt = 6 - ss;
        // dict bytes
        var db = df == 3 ? 4 : df;
        // dictionary id
        var di = rb(dat, bt, db);
        bt += db;
        // frame size bytes
        var fsb = fcf ? (1 << fcf) : ss;
        // frame source size
        var fss = rb(dat, bt, fsb) + ((fcf == 1) && 256);
        // window size
        var ws = fss;
        if (!ss) {
            // window descriptor
            var wb = 1 << (10 + (dat[5] >> 3));
            ws = wb + (wb >> 3) * (dat[5] & 7);
        }
        if (ws > 2145386496)
            err(1);
        var buf = new u8((w == 1 ? (fss || ws) : w ? 0 : ws) + 12);
        buf[0] = 1, buf[4] = 4, buf[8] = 8;
        return {
            b: bt + fsb,
            y: 0,
            l: 0,
            d: di,
            w: (w && w != 1) ? w : buf.subarray(12),
            e: ws,
            o: new i32(buf.buffer, 0, 3),
            u: fss,
            c: cc,
            m: Math.min(131072, ws)
        };
    }
    else if (((n3 >> 4) | (dat[3] << 20)) == 0x184D2A5) {
        // skippable
        return b4(dat, 4) + 8;
    }
    err(0);
};
// most significant bit for nonzero
var msb = function (val) {
    var bits = 0;
    for (; (1 << bits) <= val; ++bits)
        ;
    return bits - 1;
};
// read finite state entropy
var rfse = function (dat, bt, mal) {
    // table pos
    var tpos = (bt << 3) + 4;
    // accuracy log
    var al = (dat[bt] & 15) + 5;
    if (al > mal)
        err(3);
    // size
    var sz = 1 << al;
    // probabilities symbols  repeat   index   high threshold
    var probs = sz, sym = -1, re = -1, i = -1, ht = sz;
    // optimization: single allocation is much faster
    var buf = new ab(512 + (sz << 2));
    var freq = new i16(buf, 0, 256);
    // same view as freq
    var dstate = new u16(buf, 0, 256);
    var nstate = new u16(buf, 512, sz);
    var bb1 = 512 + (sz << 1);
    var syms = new u8(buf, bb1, sz);
    var nbits = new u8(buf, bb1 + sz);
    while (sym < 255 && probs > 0) {
        var bits = msb(probs + 1);
        var cbt = tpos >> 3;
        // mask
        var msk = (1 << (bits + 1)) - 1;
        var val = ((dat[cbt] | (dat[cbt + 1] << 8) | (dat[cbt + 2] << 16)) >> (tpos & 7)) & msk;
        // mask (1 fewer bit)
        var msk1fb = (1 << bits) - 1;
        // max small value
        var msv = msk - probs - 1;
        // small value
        var sval = val & msk1fb;
        if (sval < msv)
            tpos += bits, val = sval;
        else {
            tpos += bits + 1;
            if (val > msk1fb)
                val -= msv;
        }
        freq[++sym] = --val;
        if (val == -1) {
            probs += val;
            syms[--ht] = sym;
        }
        else
            probs -= val;
        if (!val) {
            do {
                // repeat byte
                var rbt = tpos >> 3;
                re = ((dat[rbt] | (dat[rbt + 1] << 8)) >> (tpos & 7)) & 3;
                tpos += 2;
                sym += re;
            } while (re == 3);
        }
    }
    if (sym > 255 || probs)
        err(0);
    var sympos = 0;
    // sym step (coprime with sz - formula from zstd source)
    var sstep = (sz >> 1) + (sz >> 3) + 3;
    // sym mask
    var smask = sz - 1;
    for (var s = 0; s <= sym; ++s) {
        var sf = freq[s];
        if (sf < 1) {
            dstate[s] = -sf;
            continue;
        }
        // This is split into two loops in zstd to avoid branching, but as JS is higher-level that is unnecessary
        for (i = 0; i < sf; ++i) {
            syms[sympos] = s;
            do {
                sympos = (sympos + sstep) & smask;
            } while (sympos >= ht);
        }
    }
    // After spreading symbols, should be zero again
    if (sympos)
        err(0);
    for (i = 0; i < sz; ++i) {
        // next state
        var ns = dstate[syms[i]]++;
        // num bits
        var nb = nbits[i] = al - msb(ns);
        nstate[i] = (ns << nb) - sz;
    }
    return [(tpos + 7) >> 3, {
            b: al,
            s: syms,
            n: nbits,
            t: nstate
        }];
};
// read huffman
var rhu = function (dat, bt) {
    //  index  weight count
    var i = 0, wc = -1;
    //    buffer             header byte
    var buf = new u8(292), hb = dat[bt];
    // huffman weights
    var hw = buf.subarray(0, 256);
    // rank count
    var rc = buf.subarray(256, 268);
    // rank index
    var ri = new u16(buf.buffer, 268);
    // NOTE: at this point bt is 1 less than expected
    if (hb < 128) {
        // end byte, fse decode table
        var _a = rfse(dat, bt + 1, 6), ebt = _a[0], fdt = _a[1];
        bt += hb;
        var epos = ebt << 3;
        // last byte
        var lb = dat[bt];
        if (!lb)
            err(0);
        //  state1   state2   state1 bits   state2 bits
        var st1 = 0, st2 = 0, btr1 = fdt.b, btr2 = btr1;
        // fse pos
        // pre-increment to account for original deficit of 1
        var fpos = (++bt << 3) - 8 + msb(lb);
        for (;;) {
            fpos -= btr1;
            if (fpos < epos)
                break;
            var cbt = fpos >> 3;
            st1 += ((dat[cbt] | (dat[cbt + 1] << 8)) >> (fpos & 7)) & ((1 << btr1) - 1);
            hw[++wc] = fdt.s[st1];
            fpos -= btr2;
            if (fpos < epos)
                break;
            cbt = fpos >> 3;
            st2 += ((dat[cbt] | (dat[cbt + 1] << 8)) >> (fpos & 7)) & ((1 << btr2) - 1);
            hw[++wc] = fdt.s[st2];
            btr1 = fdt.n[st1];
            st1 = fdt.t[st1];
            btr2 = fdt.n[st2];
            st2 = fdt.t[st2];
        }
        if (++wc > 255)
            err(0);
    }
    else {
        wc = hb - 127;
        for (; i < wc; i += 2) {
            var byte = dat[++bt];
            hw[i] = byte >> 4;
            hw[i + 1] = byte & 15;
        }
        ++bt;
    }
    // weight exponential sum
    var wes = 0;
    for (i = 0; i < wc; ++i) {
        var wt = hw[i];
        // bits must be at most 11, same as weight
        if (wt > 11)
            err(0);
        wes += wt && (1 << (wt - 1));
    }
    // max bits
    var mb = msb(wes) + 1;
    // table size
    var ts = 1 << mb;
    // remaining sum
    var rem = ts - wes;
    // must be power of 2
    if (rem & (rem - 1))
        err(0);
    hw[wc++] = msb(rem) + 1;
    for (i = 0; i < wc; ++i) {
        var wt = hw[i];
        ++rc[hw[i] = wt && (mb + 1 - wt)];
    }
    // huf buf
    var hbuf = new u8(ts << 1);
    //    symbols                      num bits
    var syms = hbuf.subarray(0, ts), nb = hbuf.subarray(ts);
    ri[mb] = 0;
    for (i = mb; i > 0; --i) {
        var pv = ri[i];
        fill(nb, i, pv, ri[i - 1] = pv + rc[i] * (1 << (mb - i)));
    }
    if (ri[0] != ts)
        err(0);
    for (i = 0; i < wc; ++i) {
        var bits = hw[i];
        if (bits) {
            var code = ri[bits];
            fill(syms, i, code, ri[bits] = code + (1 << (mb - bits)));
        }
    }
    return [bt, {
            n: nb,
            b: mb,
            s: syms
        }];
};
// Tables generated using this:
// https://gist.github.com/101arrowz/a979452d4355992cbf8f257cbffc9edd
// default literal length table
var dllt = /*#__PURE__*/ rfse(/*#__PURE__*/ new u8([
    81, 16, 99, 140, 49, 198, 24, 99, 12, 33, 196, 24, 99, 102, 102, 134, 70, 146, 4
]), 0, 6)[1];
// default match length table
var dmlt = /*#__PURE__*/ rfse(/*#__PURE__*/ new u8([
    33, 20, 196, 24, 99, 140, 33, 132, 16, 66, 8, 33, 132, 16, 66, 8, 33, 68, 68, 68, 68, 68, 68, 68, 68, 36, 9
]), 0, 6)[1];
// default offset code table
var doct = /*#__PURE__ */ rfse(/*#__PURE__*/ new u8([
    32, 132, 16, 66, 102, 70, 68, 68, 68, 68, 36, 73, 2
]), 0, 5)[1];
// bits to baseline
var b2bl = function (b, s) {
    var len = b.length, bl = new i32(len);
    for (var i = 0; i < len; ++i) {
        bl[i] = s;
        s += 1 << b[i];
    }
    return bl;
};
// literal length bits
var llb = /*#__PURE__ */ new u8(( /*#__PURE__ */new i32([
    0, 0, 0, 0, 16843009, 50528770, 134678020, 202050057, 269422093
])).buffer, 0, 36);
// literal length baseline
var llbl = /*#__PURE__ */ b2bl(llb, 0);
// match length bits
var mlb = /*#__PURE__ */ new u8(( /*#__PURE__ */new i32([
    0, 0, 0, 0, 0, 0, 0, 0, 16843009, 50528770, 117769220, 185207048, 252579084, 16
])).buffer, 0, 53);
// match length baseline
var mlbl = /*#__PURE__ */ b2bl(mlb, 3);
// decode huffman stream
var dhu = function (dat, out, hu) {
    var len = dat.length, ss = out.length, lb = dat[len - 1], msk = (1 << hu.b) - 1, eb = -hu.b;
    if (!lb)
        err(0);
    var st = 0, btr = hu.b, pos = (len << 3) - 8 + msb(lb) - btr, i = -1;
    for (; pos > eb && i < ss;) {
        var cbt = pos >> 3;
        var val = (dat[cbt] | (dat[cbt + 1] << 8) | (dat[cbt + 2] << 16)) >> (pos & 7);
        st = ((st << btr) | val) & msk;
        out[++i] = hu.s[st];
        pos -= (btr = hu.n[st]);
    }
    if (pos != eb || i + 1 != ss)
        err(0);
};
// decode huffman stream 4x
// TODO: use workers to parallelize
var dhu4 = function (dat, out, hu) {
    var bt = 6;
    var ss = out.length, sz1 = (ss + 3) >> 2, sz2 = sz1 << 1, sz3 = sz1 + sz2;
    dhu(dat.subarray(bt, bt += dat[0] | (dat[1] << 8)), out.subarray(0, sz1), hu);
    dhu(dat.subarray(bt, bt += dat[2] | (dat[3] << 8)), out.subarray(sz1, sz2), hu);
    dhu(dat.subarray(bt, bt += dat[4] | (dat[5] << 8)), out.subarray(sz2, sz3), hu);
    dhu(dat.subarray(bt), out.subarray(sz3), hu);
};
// read Zstandard block
var rzb = function (dat, st, out) {
    var _a;
    var bt = st.b;
    //    byte 0        block type
    var b0 = dat[bt], btype = (b0 >> 1) & 3;
    st.l = b0 & 1;
    var sz = (b0 >> 3) | (dat[bt + 1] << 5) | (dat[bt + 2] << 13);
    // end byte for block
    var ebt = (bt += 3) + sz;
    if (btype == 1) {
        if (bt >= dat.length)
            return;
        st.b = bt + 1;
        if (out) {
            fill(out, dat[bt], st.y, st.y += sz);
            return out;
        }
        return fill(new u8(sz), dat[bt]);
    }
    if (ebt > dat.length)
        return;
    if (btype == 0) {
        st.b = ebt;
        if (out) {
            out.set(dat.subarray(bt, ebt), st.y);
            st.y += sz;
            return out;
        }
        return slc(dat, bt, ebt);
    }
    if (btype == 2) {
        //    byte 3        lit btype     size format
        var b3 = dat[bt], lbt = b3 & 3, sf = (b3 >> 2) & 3;
        // lit src size  lit cmp sz 4 streams
        var lss = b3 >> 4, lcs = 0, s4 = 0;
        if (lbt < 2) {
            if (sf & 1)
                lss |= (dat[++bt] << 4) | ((sf & 2) && (dat[++bt] << 12));
            else
                lss = b3 >> 3;
        }
        else {
            s4 = sf;
            if (sf < 2)
                lss |= ((dat[++bt] & 63) << 4), lcs = (dat[bt] >> 6) | (dat[++bt] << 2);
            else if (sf == 2)
                lss |= (dat[++bt] << 4) | ((dat[++bt] & 3) << 12), lcs = (dat[bt] >> 2) | (dat[++bt] << 6);
            else
                lss |= (dat[++bt] << 4) | ((dat[++bt] & 63) << 12), lcs = (dat[bt] >> 6) | (dat[++bt] << 2) | (dat[++bt] << 10);
        }
        ++bt;
        // add literals to end - can never overlap with backreferences because unused literals always appended
        var buf = out ? out.subarray(st.y, st.y + st.m) : new u8(st.m);
        // starting point for literals
        var spl = buf.length - lss;
        if (lbt == 0)
            buf.set(dat.subarray(bt, bt += lss), spl);
        else if (lbt == 1)
            fill(buf, dat[bt++], spl);
        else {
            // huffman table
            var hu = st.h;
            if (lbt == 2) {
                var hud = rhu(dat, bt);
                // subtract description length
                lcs += bt - (bt = hud[0]);
                st.h = hu = hud[1];
            }
            else if (!hu)
                err(0);
            (s4 ? dhu4 : dhu)(dat.subarray(bt, bt += lcs), buf.subarray(spl), hu);
        }
        // num sequences
        var ns = dat[bt++];
        if (ns) {
            if (ns == 255)
                ns = (dat[bt++] | (dat[bt++] << 8)) + 0x7F00;
            else if (ns > 127)
                ns = ((ns - 128) << 8) | dat[bt++];
            // symbol compression modes
            var scm = dat[bt++];
            if (scm & 3)
                err(0);
            var dts = [dmlt, doct, dllt];
            for (var i = 2; i > -1; --i) {
                var md = (scm >> ((i << 1) + 2)) & 3;
                if (md == 1) {
                    // rle buf
                    var rbuf = new u8([0, 0, dat[bt++]]);
                    dts[i] = {
                        s: rbuf.subarray(2, 3),
                        n: rbuf.subarray(0, 1),
                        t: new u16(rbuf.buffer, 0, 1),
                        b: 0
                    };
                }
                else if (md == 2) {
                    // accuracy log 8 for offsets, 9 for others
                    _a = rfse(dat, bt, 9 - (i & 1)), bt = _a[0], dts[i] = _a[1];
                }
                else if (md == 3) {
                    if (!st.t)
                        err(0);
                    dts[i] = st.t[i];
                }
            }
            var _b = st.t = dts, mlt = _b[0], oct = _b[1], llt = _b[2];
            var lb = dat[ebt - 1];
            if (!lb)
                err(0);
            var spos = (ebt << 3) - 8 + msb(lb) - llt.b, cbt = spos >> 3, oubt = 0;
            var lst = ((dat[cbt] | (dat[cbt + 1] << 8)) >> (spos & 7)) & ((1 << llt.b) - 1);
            cbt = (spos -= oct.b) >> 3;
            var ost = ((dat[cbt] | (dat[cbt + 1] << 8)) >> (spos & 7)) & ((1 << oct.b) - 1);
            cbt = (spos -= mlt.b) >> 3;
            var mst = ((dat[cbt] | (dat[cbt + 1] << 8)) >> (spos & 7)) & ((1 << mlt.b) - 1);
            for (++ns; --ns;) {
                var llc = llt.s[lst];
                var lbtr = llt.n[lst];
                var mlc = mlt.s[mst];
                var mbtr = mlt.n[mst];
                var ofc = oct.s[ost];
                var obtr = oct.n[ost];
                cbt = (spos -= ofc) >> 3;
                var ofp = 1 << ofc;
                var off = ofp + (((dat[cbt] | (dat[cbt + 1] << 8) | (dat[cbt + 2] << 16) | (dat[cbt + 3] << 24)) >>> (spos & 7)) & (ofp - 1));
                cbt = (spos -= mlb[mlc]) >> 3;
                var ml = mlbl[mlc] + (((dat[cbt] | (dat[cbt + 1] << 8) | (dat[cbt + 2] << 16)) >> (spos & 7)) & ((1 << mlb[mlc]) - 1));
                cbt = (spos -= llb[llc]) >> 3;
                var ll = llbl[llc] + (((dat[cbt] | (dat[cbt + 1] << 8) | (dat[cbt + 2] << 16)) >> (spos & 7)) & ((1 << llb[llc]) - 1));
                cbt = (spos -= lbtr) >> 3;
                lst = llt.t[lst] + (((dat[cbt] | (dat[cbt + 1] << 8)) >> (spos & 7)) & ((1 << lbtr) - 1));
                cbt = (spos -= mbtr) >> 3;
                mst = mlt.t[mst] + (((dat[cbt] | (dat[cbt + 1] << 8)) >> (spos & 7)) & ((1 << mbtr) - 1));
                cbt = (spos -= obtr) >> 3;
                ost = oct.t[ost] + (((dat[cbt] | (dat[cbt + 1] << 8)) >> (spos & 7)) & ((1 << obtr) - 1));
                if (off > 3) {
                    st.o[2] = st.o[1];
                    st.o[1] = st.o[0];
                    st.o[0] = off -= 3;
                }
                else {
                    var idx = off - (ll != 0);
                    if (idx) {
                        off = idx == 3 ? st.o[0] - 1 : st.o[idx];
                        if (idx > 1)
                            st.o[2] = st.o[1];
                        st.o[1] = st.o[0];
                        st.o[0] = off;
                    }
                    else
                        off = st.o[0];
                }
                for (var i = 0; i < ll; ++i) {
                    buf[oubt + i] = buf[spl + i];
                }
                oubt += ll, spl += ll;
                var stin = oubt - off;
                if (stin < 0) {
                    var len = -stin;
                    var bs = st.e + stin;
                    if (len > ml)
                        len = ml;
                    for (var i = 0; i < len; ++i) {
                        buf[oubt + i] = st.w[bs + i];
                    }
                    oubt += len, ml -= len, stin = 0;
                }
                for (var i = 0; i < ml; ++i) {
                    buf[oubt + i] = buf[stin + i];
                }
                oubt += ml;
            }
            if (oubt != spl) {
                while (spl < buf.length) {
                    buf[oubt++] = buf[spl++];
                }
            }
            else
                oubt = buf.length;
            if (out)
                st.y += oubt;
            else
                buf = slc(buf, 0, oubt);
        }
        else if (out) {
            st.y += lss;
            if (spl) {
                for (var i = 0; i < lss; ++i) {
                    buf[i] = buf[spl + i];
                }
            }
        }
        else if (spl)
            buf = slc(buf, spl);
        st.b = ebt;
        return buf;
    }
    err(2);
};
// concat
var cct = function (bufs, ol) {
    if (bufs.length == 1)
        return bufs[0];
    var buf = new u8(ol);
    for (var i = 0, b = 0; i < bufs.length; ++i) {
        var chk = bufs[i];
        buf.set(chk, b);
        b += chk.length;
    }
    return buf;
};
/**
 * Decompresses Zstandard data
 * @param dat The input data
 * @param buf The output buffer. If unspecified, the function will allocate
 *            exactly enough memory to fit the decompressed data. If your
 *            data has multiple frames and you know the output size, specifying
 *            it will yield better performance.
 * @returns The decompressed data
 */
function decompress(dat, buf) {
    var bufs = [], nb = +!buf;
    var bt = 0, ol = 0;
    for (; dat.length;) {
        var st = rzfh(dat, nb || buf);
        if (typeof st == 'object') {
            if (nb) {
                buf = null;
                if (st.w.length == st.u) {
                    bufs.push(buf = st.w);
                    ol += st.u;
                }
            }
            else {
                bufs.push(buf);
                st.e = 0;
            }
            for (; !st.l;) {
                var blk = rzb(dat, st, buf);
                if (!blk)
                    err(5);
                if (buf)
                    st.e = st.y;
                else {
                    bufs.push(blk);
                    ol += blk.length;
                    cpw(st.w, 0, blk.length);
                    st.w.set(blk, st.w.length - blk.length);
                }
            }
            bt = st.b + (st.c * 4);
        }
        else
            bt = st;
        dat = dat.subarray(bt);
    }
    return cct(bufs, ol);
}
/**
 * Decompressor for Zstandard streamed data
 */
var Decompress = /*#__PURE__*/ (function () {
    /**
     * Creates a Zstandard decompressor
     * @param ondata The handler for stream data
     */
    function Decompress(ondata) {
        this.ondata = ondata;
        this.c = [];
        this.l = 0;
        this.z = 0;
    }
    /**
     * Pushes data to be decompressed
     * @param chunk The chunk of data to push
     * @param final Whether or not this is the last chunk in the stream
     */
    Decompress.prototype.push = function (chunk, final) {
        if (typeof this.s == 'number') {
            var sub = Math.min(chunk.length, this.s);
            chunk = chunk.subarray(sub);
            this.s -= sub;
        }
        var sl = chunk.length;
        var ncs = sl + this.l;
        if (!this.s) {
            if (final) {
                if (!ncs) {
                    this.ondata(new u8(0), true);
                    return;
                }
                // min for frame + one block
                if (ncs < 5)
                    err(5);
            }
            else if (ncs < 18) {
                this.c.push(chunk);
                this.l = ncs;
                return;
            }
            if (this.l) {
                this.c.push(chunk);
                chunk = cct(this.c, ncs);
                this.c = [];
                this.l = 0;
            }
            if (typeof (this.s = rzfh(chunk)) == 'number')
                return this.push(chunk, final);
        }
        if (typeof this.s != 'number') {
            if (ncs < (this.z || 3)) {
                if (final)
                    err(5);
                this.c.push(chunk);
                this.l = ncs;
                return;
            }
            if (this.l) {
                this.c.push(chunk);
                chunk = cct(this.c, ncs);
                this.c = [];
                this.l = 0;
            }
            if (!this.z && ncs < (this.z = (chunk[this.s.b] & 2) ? 4 : 3 + ((chunk[this.s.b] >> 3) | (chunk[this.s.b + 1] << 5) | (chunk[this.s.b + 2] << 13)))) {
                if (final)
                    err(5);
                this.c.push(chunk);
                this.l = ncs;
                return;
            }
            else
                this.z = 0;
            for (;;) {
                var blk = rzb(chunk, this.s);
                if (!blk) {
                    if (final)
                        err(5);
                    var adc = chunk.subarray(this.s.b);
                    this.s.b = 0;
                    this.c.push(adc), this.l += adc.length;
                    return;
                }
                else {
                    this.ondata(blk, false);
                    cpw(this.s.w, 0, blk.length);
                    this.s.w.set(blk, this.s.w.length - blk.length);
                }
                if (this.s.l) {
                    var rest = chunk.subarray(this.s.b);
                    this.s = this.s.c * 4;
                    this.push(rest, final);
                    return;
                }
            }
        }
        else if (final)
            err(5);
    };
    return Decompress;
}());
  return { decompress: decompress };
})();

/* ---------- utilidades de leitura binária ---------- */
const UTF8_DECODER = new TextDecoder('utf-8');
function utf8Slice(bytes, s, e) { return UTF8_DECODER.decode(bytes.subarray(s, e)); }
function hexSlice(bytes, s, e) {
  let out = '';
  for (let i = s; i < e; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}
function dvOf(bytes) { return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength); }

class SaveError extends Error {
  constructor(code, message) { super(message); this.code = code; this.name = 'SaveError'; }
}

/* ---------- leitor de manifesto (Cursor) ---------- */
class Cursor {
  constructor(buffer, pos = 0) {
    this.buffer = buffer;
    this.dv = dvOf(buffer);
    this.pos = pos;
  }
  need(n) {
    if (!Number.isSafeInteger(n) || n < 0 || this.pos + n > this.buffer.length)
      throw new SaveError('TRUNCATED', 'O save contém um registo incompleto.');
  }
  u32() {
    this.need(4);
    const n = this.dv.getUint32(this.pos, true);
    this.pos += 4;
    return n;
  }
  u64() {
    this.need(8);
    const n = Number(this.dv.getBigUint64(this.pos, true));
    this.pos += 8;
    if (!Number.isSafeInteger(n)) throw new SaveError('INVALID_SIZE', 'Um membro do arquivo é demasiado grande.');
    return n;
  }
  text() {
    const n = this.u32();
    if (n > 16384) throw new SaveError('INVALID_MANIFEST', 'Um nome de arquivo tem um comprimento inválido.');
    this.need(n);
    const s = utf8Slice(this.buffer, this.pos, this.pos + n);
    this.pos += n;
    return s;
  }
}

/* ---------- arquivo do save (formato FM24, comprimido em zstd) ---------- */
class SaveArchive {
  constructor(raw) {
    this.raw = raw;
    this.size = raw.length;
    const h = this.read(0, 26);
    if (hexSlice(h, 0, 6) !== '0201666d662e' || h[6] !== 8)
      throw new SaveError('UNSUPPORTED_FORMAT', 'Este ficheiro não é um arquivo de save FM24 suportado.');
    if (h[25] !== 0 && h[25] !== 3)
      throw new SaveError('UNSUPPORTED_COMPRESSION', 'Este save usa um método de compressão não suportado.');
    this.compressed = h[25] === 3;
    const hDv = dvOf(h);
    this.manifestStart = Number(hDv.getBigUint64(9, true)) + 9;
    const mh = this.read(this.manifestStart, 13);
    if (hexSlice(mh, 0, 9) !== '0201666d662e080000' || hexSlice(mh, 9, 13) !== '28b52ffd')
      throw new SaveError('INVALID_MANIFEST', 'O índice do save está em falta ou incompleto. Tenta um save de backup completo.');
    const tailSize = this.size - this.manifestStart - 9;
    if (tailSize > 32 * 1024 * 1024)
      throw new SaveError('INVALID_MANIFEST', 'O índice do save excede o tamanho suportado.');
    let bytes;
    try {
      bytes = Zstd.decompress(this.read(this.manifestStart + 9, tailSize));
    } catch {
      throw new SaveError('CORRUPT_COMPRESSION', 'Não foi possível descomprimir o índice do save.');
    }
    const c = new Cursor(bytes);
    this.name = c.text();
    this.members = [];
    const group = (prefix) => {
      const count = c.u32();
      if (count > 100000) throw new SaveError('INVALID_MANIFEST', 'Número inválido de membros no arquivo.');
      for (let i = 0; i < count; i++) {
        let name = '', part = '', parts = 0;
        do {
          part = c.text();
          name += part;
          if (++parts > 20) throw new SaveError('INVALID_MANIFEST', 'Nome de membro inválido.');
        } while (!part.startsWith('.'));
        const offset = c.u64(), stored = c.u64(), plain = c.u64();
        c.need(16);
        c.pos += 16;
        if (offset < 0 || stored < 0 || offset + stored + 26 > this.manifestStart || plain > 2 * 1024 ** 3)
          throw new SaveError('INVALID_SIZE', 'Um membro do save tem limites inválidos ou excede 2 GB.');
        this.members.push({ name: prefix + name, offset, stored, plain });
      }
    };
    group('');
    const groups = c.u32();
    if (groups > 10000) throw new SaveError('INVALID_MANIFEST', 'Número inválido de grupos no arquivo.');
    for (let i = 0; i < groups; i++) group(c.text() + '/');
    if (!this.members.some((m) => m.name === 'game_db.dat'))
      throw new SaveError('MISSING_DATABASE', 'O save não contém uma base de dados de jogadores.');
  }
  read(position, length) {
    if (!Number.isSafeInteger(position) || !Number.isSafeInteger(length) || position < 0 || length < 0 || position + length > this.size)
      throw new SaveError('TRUNCATED', 'O ficheiro de save está incompleto.');
    return this.raw.subarray(position, position + length);
  }
  member(name) {
    const m = this.members.find((m) => m.name === name);
    if (!m) throw new SaveError('MISSING_MEMBER', `O save não contém ${name}.`);
    const stored = this.read(m.offset + 26, m.stored);
    let b;
    try {
      b = this.compressed ? Zstd.decompress(stored) : stored;
    } catch {
      throw new SaveError('CORRUPT_COMPRESSION', `Não foi possível descomprimir ${name}.`);
    }
    if (b.length !== m.plain) throw new SaveError('INVALID_SIZE', `${name} tem um tamanho inesperado.`);
    return b;
  }
}

/* ---------- tabelas de nomes ---------- */
function readPool(b, dv, start) {
  if (start + 16 >= b.length) return null;
  const count = dv.getUint32(start, true);
  if (count < 1 || count > 3000000) return null;
  const names = [];
  let p = start + 4;
  for (let id = 0; id < count; id++) {
    if (p + 8 > b.length || dv.getUint32(p, true) !== id) return null;
    const n = dv.getUint32(p + 4, true);
    if (n > 512 || p + 8 + n > b.length) return null;
    const s = utf8Slice(b, p + 8, p + 8 + n);
    if (/[\u0000-\u001f\ufffd]/.test(s)) return null;
    names.push(s);
    p += 8 + n;
  }
  return { names, end: p };
}
function readNames(b, dv) {
  for (let p = 0; p + 40 < b.length; p++) {
    if (b[p + 7] !== 0 || b[p + 6] !== 0 || b[p + 5] !== 0 || b[p + 4] !== 0) continue;
    const count = dv.getUint32(p, true);
    if (count < 10000 || count > 3000000) continue;
    const n = dv.getUint32(p + 8, true);
    if (n < 1 || n > 100 || p + 16 + n > b.length || dv.getUint32(p + 12 + n, true) !== 1) continue;
    const first = readPool(b, dv, p);
    if (!first) continue;
    const last = readPool(b, dv, first.end);
    if (!last || last.names.length < 10000) continue;
    const common = readPool(b, dv, last.end);
    if (!common) continue;
    return { first: first.names, last: last.names, common: common.names, start: p, end: common.end };
  }
  throw new SaveError('UNSUPPORTED_NAMES', 'Não foi possível localizar as tabelas de nomes FM24 neste save.');
}

/* ---------- pessoas, capacidades, ligação pessoa<->capacidade ---------- */
async function readPeople(b, dv, names, onProgress = () => {}) {
  const people = [];
  const p0 = names.end, pSpan = Math.max(1, b.length - 100 - p0);
  for (let p = names.end; p < b.length - 100; p++) {
    if ((p - p0) % SCAN_CHUNK === 0) { onProgress(0.55 * (p - p0) / pSpan); await tick(); }
    if (b[p + 4] || b[p + 9] || b[p + 14] || b[p + 17] || b[p + 18]) continue;
    const f = dv.getUint32(p, true), l = dv.getUint32(p + 5, true), n = dv.getUint32(p + 15, true);
    if ((f !== 0xffffffff && f >= names.first.length) || (l !== 0xffffffff && l >= names.last.length) || n > 200) continue;
    const end = p + 19 + n;
    if (end + 45 > b.length) continue;
    const day = dv.getUint16(end, true), year = dv.getUint16(end + 2, true), nation = dv.getUint16(end + 9, true);
    if (day < 1 || day > 366 || year < 1850 || year > 2300 || nation > 255) continue;
    if (!b.subarray(end + 11, end + 17).every((v) => v === 0) ||
        !b.subarray(end + 17, end + 25).every((v) => v >= 1 && v <= 20))
      continue;
    const fullName = utf8Slice(b, p + 19, end);
    if (/[\u0000-\u001f\ufffd]/.test(fullName)) continue;
    const name = `${names.first[f] ?? ''} ${names.last[l] ?? ''}`.trim() || fullName;
    if (!name) continue;
    people.push({
      offset: p, end, id: -1, uid: -1, name, fullName: fullName || name,
      birthDay: day, birthYear: year, nation,
      personality: Array.from(b.subarray(end + 17, end + 25)),
      otherNations: [], identityOffset: 0,
    });
    p = end + 24;
  }
  const maxId = dv.getUint32(names.end, true) + 1;
  const identities = [];
  const p1 = names.end + 7, p1Span = Math.max(1, b.length - 12 - p1);
  for (let p = names.end + 7; p < b.length - 12; p++) {
    if ((p - p1) % SCAN_CHUNK === 0) { onProgress(0.55 + 0.35 * (p - p1) / p1Span); await tick(); }
    if (b[p - 1] || b[p - 2] || b[p - 3] || (b[p - 7] & 7) > 2 || ![0, 1, 4, 5].includes(b[p - 4]))
      continue;
    const id = dv.getUint32(p, true), uid = dv.getUint32(p + 4, true);
    if (id >= maxId || !uid || uid === 0xffffffff) continue;
    if (uid !== dv.getUint32(p + 8, true)) {
      if (p < 12) continue;
      const day = dv.getUint16(p - 12, true) & 511, year = dv.getUint16(p - 10, true), sourceUid = dv.getUint32(p + 8, true);
      if (day < 1 || day > 366 || year < 1900 || year > 2300 || (b[p - 6] & 0x85) !== 0 || (b[p - 6] & 0x60) === 0 || sourceUid < 1000 || sourceUid === 0xffffffff)
        continue;
    }
    if ((id & 255) === 0 && (uid & 255) === 0 && dv.getUint32(p + 5, true) === dv.getUint32(p + 9, true))
      continue;
    identities.push({ offset: p, id, uid });
  }
  const tails = [], tailIndices = [], prev = new Int32Array(identities.length).fill(-1);
  for (let i = 0; i < identities.length; i++) {
    const id = identities[i].id;
    let lo = 0, hi = tails.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (tails[mid] < id) lo = mid + 1; else hi = mid;
    }
    prev[i] = lo ? tailIndices[lo - 1] : -1;
    tails[lo] = id;
    tailIndices[lo] = i;
  }
  const ordered = [];
  let ix = tailIndices.length ? tailIndices[tailIndices.length - 1] : -1;
  while (ix >= 0) {
    ordered.push(identities[ix]);
    ix = prev[ix];
  }
  ordered.reverse();
  let j = 0;
  for (let i = 0; i < people.length; i++) {
    const person = people[i], end = people[i + 1] ? people[i + 1].offset : b.length;
    while (j < ordered.length && ordered[j].offset < person.end + 25) j++;
    const identity = ordered[j];
    if (!identity || identity.offset >= end) continue;
    person.id = identity.id;
    person.uid = identity.uid;
    person.identityOffset = identity.offset;
    const count = b[person.end + 34];
    if (b[person.end + 33] === 1 && person.end + 35 + count * 16 <= identity.offset) {
      for (let k = 0; k < count; k++) {
        const p = person.end + 35 + k * 16;
        const n = dv.getUint32(p, true);
        if (n < 256 && n !== person.nation && b.subarray(p + 4, p + 8).every((v) => v === 0) &&
            b[p + 10] === 8 && [9, 70].includes(b[p + 11]) && !person.otherNations.includes(n))
          person.otherNations.push(n);
      }
    }
  }
  return people;
}
async function readAbilities(b, dv, start, onProgress = () => {}) {
  const blocks = [];
  const p0 = start + 57, pSpan = Math.max(1, b.length - 54 - p0);
  for (let p = start + 57; p < b.length - 54; p++) {
    if ((p - p0) % SCAN_CHUNK === 0) { onProgress((p - p0) / pSpan); await tick(); }
    if (b[p - 37] || b[p - 35]) continue;
    const ca = b[p - 38], pa = b[p - 36];
    if (ca < 1 || ca > 200 || pa < 1 || pa > 200) continue;
    let ok = true, natural = false;
    for (let j = -15; j < 0; j++) {
      const v = b[p + j];
      if (v < 1 || v > 20) { ok = false; break; }
      if (v === 20) natural = true;
    }
    if (!ok || !natural) continue;
    for (let j = 0; j < 54; j++) {
      const v = b[p + j];
      if (v < 1 || v > 100) { ok = false; break; }
    }
    if (!ok) continue;
    const uid = dv.getUint32(p - 53, true), sourceUid = dv.getUint32(p - 49, true);
    if (!uid || uid === 0xffffffff || !sourceUid || sourceUid === 0xffffffff) continue;
    blocks.push({
      offset: p,
      ownerId: dv.getUint32(p - 57, true) + 1,
      ca, pa,
      team: dv.getUint32(p - 23, true),
      positions: Array.from(b.subarray(p - 15, p)),
      raw: Array.from(b.subarray(p, p + 54)),
    });
    p += 53;
  }
  return blocks;
}
function linkAbilities(people, blocks) {
  const linked = [];
  let i = 0, ambiguous = 0, unbound = 0;
  for (const person of people) {
    const first = i;
    while (i < blocks.length && blocks[i].offset < person.offset) i++;
    if (first === i) continue;
    if (i - first !== 1) { ambiguous++; continue; }
    if (person.id < 0 || blocks[first].ownerId !== person.id) { unbound++; continue; }
    linked.push({ person, ability: blocks[first] });
  }
  return { linked, ambiguous, unbound };
}

/* ---------- clubes ---------- */
function readClubs(b, dv, end) {
  const clubs = [];
  for (let p = 0; p + 50 < end; p++) {
    if (b[p + 12] || b[p + 17] !== 255 || b[p + 18] !== 255 || b[p + 19] !== 255 || b[p + 20] !== 255) continue;
    const nation = dv.getUint32(p + 13, true);
    if (nation > 255 || dv.getUint32(p + 25, true) !== nation) continue;
    const uid = dv.getUint32(p + 4, true), id = dv.getUint32(p, true);
    if (!uid || uid === 0xffffffff || uid !== dv.getUint32(p + 8, true) || id > 100000) continue;
    const n = dv.getUint32(p + 39, true);
    if (n < 2 || n > 200 || p + 47 + n >= end) continue;
    const sn = dv.getUint32(p + 43 + n, true);
    if (sn < 1 || sn > 100 || p + 47 + n + sn > end) continue;
    const name = utf8Slice(b, p + 43, p + 43 + n), shortName = utf8Slice(b, p + 47 + n, p + 47 + n + sn);
    if (/[\u0000-\u001f\ufffd]/.test(name + shortName)) continue;
    clubs.push({ id, uid, nation, name, shortName, offset: p });
    p += 46 + n + sn;
  }
  return clubs;
}

/* ---------- equipas/plantéis ---------- */
function readTeams(b, dv, clubs, end, validPeople) {
  const clubMap = new Map(clubs.map((c) => [c.id, c]));
  const heads = [];
  for (let p = 4; p < end - 70; p++) {
    if (b[p + 26] !== 10 || b[p + 4] || b[p + 5] || b[p + 6] || b[p + 7] || b[p + 8] || b[p + 9] || b[p + 10] || b[p + 11] || b[p + 12] || b[p + 13])
      continue;
    const owner = dv.getUint32(p, true), ordinal = dv.getUint32(p + 14, true), uid = dv.getUint32(p + 18, true);
    if (owner > 100000 || ordinal > 500000 || !uid) continue;
    const typed = b[p - 4] === 1 && b[p - 2] === 255 && [18, 19, 20, 21, 23, 100].includes(b[p - 3]);
    const club = clubMap.get(owner), matched = club && club.uid === uid && dv.getUint32(p + 22, true) === uid;
    if (!typed && !matched) continue;
    heads.push({ offset: p, owner, ordinal, uid, typed, type: typed ? b[p - 3] : 100, flag: typed ? b[p - 1] : 0 });
    p += 25;
  }
  const teams = [];
  for (let i = 0; i < heads.length; i++) {
    const h = heads[i], limit = Math.min(heads[i + 1] ? heads[i + 1].offset : end, h.offset + 10000);
    let club = null;
    const ownerClub = clubMap.get(h.owner);
    if (ownerClub && ownerClub.uid === h.uid) club = h.owner;
    else if (h.typed && !(h.type === 100 && h.flag & 32) && h.owner > 256) {
      const id = [20, 23].includes(h.type) ? h.owner - 1 : h.owner;
      if (clubMap.has(id)) club = id;
    }
    const members = [];
    for (let p = h.offset + 30; p + 14 < limit; p++) {
      if (b[p] !== 255 || dv.getUint32(p, true) !== 0xffffffff) continue;
      const count = dv.getUint16(p + 4, true);
      if (!count || count > 150 || p + 6 + count * 4 + 8 > limit) continue;
      const ids = Array.from({ length: count }, (_, k) => dv.getUint32(p + 6 + k * 4, true));
      const set = new Set(ids);
      if (set.size !== count || ids.some((id) => id > 3000000)) continue;
      const captain = dv.getUint32(p + 6 + count * 4, true), vice = dv.getUint32(p + 10 + count * 4, true);
      if ((captain !== 0xffffffff && !set.has(captain)) || (vice !== 0xffffffff && !set.has(vice))) continue;
      if (ids.filter((id) => validPeople.has(id)).length < Math.max(1, count * 0.7)) continue;
      members.push(...ids);
      break;
    }
    teams.push({ offset: h.offset, club, ordinal: h.ordinal, type: h.type, members });
  }
  return teams;
}

/* ---------- catálogo de atributos ---------- */
const ATTR_LAYOUT = [
  ['crossing','Crossing','Technical'],['dribbling','Dribbling','Technical'],['finishing','Finishing','Technical'],
  ['heading','Heading','Technical'],['longShots','Long shots','Technical'],['marking','Marking','Technical'],
  ['offTheBall','Off the ball','Mental'],['passing','Passing','Technical'],['penaltyTaking','Penalty taking','Technical'],
  ['tackling','Tackling','Technical'],['vision','Vision','Mental'],['handling','Handling','Goalkeeping'],
  ['aerialReach','Aerial reach','Goalkeeping'],['commandOfArea','Command of area','Goalkeeping'],
  ['communication','Communication','Goalkeeping'],['kicking','Kicking','Goalkeeping'],['throwing','Throwing','Goalkeeping'],
  ['anticipation','Anticipation','Mental'],['decisions','Decisions','Mental'],['oneOnOnes','One on ones','Goalkeeping'],
  ['positioning','Positioning','Mental'],['reflexes','Reflexes','Goalkeeping'],['firstTouch','First touch','Technical'],
  ['technique','Technique','Technical'],['leftFoot','Left foot','Feet'],['rightFoot','Right foot','Feet'],
  ['flair','Flair','Mental'],['corners','Corners','Technical'],['teamwork','Teamwork','Mental'],['workRate','Work rate','Mental'],
  ['longThrows','Long throws','Technical'],['eccentricity','Eccentricity','Goalkeeping'],['rushingOut','Rushing out tendency','Goalkeeping'],
  ['punching','Punching tendency','Goalkeeping'],['acceleration','Acceleration','Physical'],['freeKickTaking','Free kick taking','Technical'],
  ['strength','Strength','Physical'],['stamina','Stamina','Physical'],['pace','Pace','Physical'],['jumpingReach','Jumping reach','Physical'],
  ['leadership','Leadership','Mental'],['dirtiness','Dirtiness','Hidden'],['balance','Balance','Physical'],['bravery','Bravery','Mental'],
  ['consistency','Consistency','Hidden'],['aggression','Aggression','Mental'],['agility','Agility','Physical'],
  ['importantMatches','Important matches','Hidden'],['injuryProneness','Injury proneness','Hidden'],['versatility','Versatility','Hidden'],
  ['naturalFitness','Natural fitness','Physical'],['determination','Determination','Mental'],['composure','Composure','Mental'],
  ['concentration','Concentration','Mental'],
];
const ATTR_PERSONALITY = [
  ['adaptability','Adaptability'],['ambition','Ambition'],['loyalty','Loyalty'],['pressure','Pressure'],
  ['professionalism','Professionalism'],['sportsmanship','Sportsmanship'],['temperament','Temperament'],['controversy','Controversy'],
];
const INVERTED_ATTRS = new Set(['dirtiness', 'injuryProneness', 'controversy']);
const ATTRIBUTES = [
  ...ATTR_LAYOUT.map(([key, label, group], index) => ({ key, label, group, index, scale: 5, inverted: INVERTED_ATTRS.has(key) })),
  ...ATTR_PERSONALITY.map(([key, label], index) => ({ key, label, group: 'Hidden', index: index + 54, scale: 1, inverted: INVERTED_ATTRS.has(key) })),
];
const POSITIONS = ['GK', 'SW', 'DL', 'DC', 'DR', 'DM', 'ML', 'MC', 'MR', 'AML', 'AMC', 'AMR', 'ST', 'WBL', 'WBR'];
function displayAttribute(raw) { return Math.max(1, Math.min(20, Math.round(raw / 5))); }

/* Devolve controlo ao browser (pintura da barra de progresso, capacidade de resposta
   da aba). Em saves grandes, os varrimentos byte-a-byte abaixo podem demorar vários
   segundos; sem isto o separador fica bloqueado do início ao fim sem qualquer
   feedback visual, dando a sensação de estar "preso". */
function tick() { return new Promise((r) => setTimeout(r, 0)); }
const SCAN_CHUNK = 8_000_000;


/* ---------- histórico de carreira, competições e dados ---------- */
const ZSTD_MAGIC = [0x28, 0xb5, 0x2f, 0xfd];
function findMagic(bytes, from = 0) {
  for (let i = Math.max(0, from); i + 4 <= bytes.length; i++) {
    if (bytes[i] === 0x28 && bytes[i + 1] === 0xb5 && bytes[i + 2] === 0x2f && bytes[i + 3] === 0xfd) return i;
  }
  return -1;
}
function zstdFrameEnd(bytes, start) {
  if (start < 0 || start + 6 > bytes.length || findMagic(bytes, start) !== start) throw new Error('Frame Zstandard inválida.');
  const flags = bytes[start + 4];
  if (flags & 8) throw new Error('Cabeçalho Zstandard inválido.');
  const single = (flags >> 5) & 1, checksum = (flags >> 2) & 1, dictFlag = flags & 3, contentFlag = flags >> 6;
  let p = start + 5;
  if (!single) p++;
  p += dictFlag === 3 ? 4 : dictFlag;
  p += contentFlag ? (1 << contentFlag) : (single ? 1 : 0);
  while (true) {
    if (p + 3 > bytes.length) throw new Error('Frame Zstandard incompleta.');
    const header = bytes[p] | (bytes[p + 1] << 8) | (bytes[p + 2] << 16);
    p += 3;
    const last = header & 1, type = (header >> 1) & 3, size = header >>> 3;
    if (type === 3) throw new Error('Bloco Zstandard inválido.');
    p += type === 1 ? 1 : size;
    if (p > bytes.length) throw new Error('Bloco Zstandard truncado.');
    if (last) break;
  }
  p += checksum ? 4 : 0;
  if (p > bytes.length) throw new Error('Checksum Zstandard truncado.');
  return p;
}
function forEachInnerBlock(bytes, callback) {
  let p = findMagic(bytes);
  while (p >= 0) {
    try {
      const end = zstdFrameEnd(bytes, p);
      const block = Zstd.decompress(bytes.subarray(p, end));
      callback(block);
      p = findMagic(bytes, end);
    } catch {
      p = findMagic(bytes, p + 4);
    }
  }
}
function concatBytes(parts) {
  const size = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}
function dateFromPacked(bytes, offset) {
  if (offset < 0 || offset + 4 > bytes.length) return null;
  const dv = dvOf(bytes), day = dv.getUint16(offset, true) & 511, year = dv.getUint16(offset + 2, true);
  if (day < 1 || day > 366 || year < 1900 || year > 2200) return null;
  try {
    const date = new Date(Date.UTC(year, 0, day));
    return date.getUTCFullYear() === year ? date.toISOString().slice(0, 10) : null;
  } catch { return null; }
}
function seasonStartOf(date) {
  const year = Number(date.slice(0, 4)), month = Number(date.slice(5, 7));
  return month >= 7 ? year : year - 1;
}
function readCompetitionKeys(gameDb) {
  const keys = new Map();
  for (let p = 0; p + 24 <= gameDb.length; p++) {
    if ((gameDb[p] !== 7 && gameDb[p] !== 8) || (gameDb[p + 4] !== 7 && gameDb[p + 4] !== 8) ||
        gameDb[p + 5] !== 0 || gameDb[p + 7] !== 255 || gameDb[p + 20] !== 0 ||
        gameDb[p + 23] !== 1) continue;
    const second = gameDb[p + 21] === 0 && gameDb[p + 22] === 0;
    const third = gameDb[p + 21] === 255 && gameDb[p + 22] === 255;
    if (!second && !third) continue;
    const key = dvOf(gameDb).getUint32(p + 8, true);
    const uid = dvOf(gameDb).getUint32(p + 12, true);
    if (uid === dvOf(gameDb).getUint32(p + 16, true) && key < 100000 && uid > 0) keys.set(key, uid);
  }
  return keys;
}
function readCompetitionStages(gameDb, keys) {
  const found = [], dv = dvOf(gameDb);
  for (let p = 0; p + 17 <= gameDb.length; p++) {
    const index = dv.getUint32(p, true);
    if (dv.getUint32(p + 4, true) !== index + 1 || dv.getUint32(p + 8, true) !== index + 1 || gameDb[p + 12] !== 0) continue;
    const key = dv.getUint32(p + 13, true);
    if (key < 100000 && keys.has(key)) found.push({ position: p, number: index + 1, key });
  }
  if (!found.length) return new Map();
  const rows = found.filter((row, i) =>
    (i > 0 && row.position - found[i - 1].position <= 100) ||
    (i + 1 < found.length && found[i + 1].position - row.position <= 100)
  );
  if (!rows.length) return new Map();
  const middle = rows.map(row => row.position).sort((a, b) => a - b)[Math.floor(rows.length / 2)];
  const stages = new Map(), nearest = new Map();
  for (const row of rows) {
    const distance = Math.abs(row.position - middle);
    if (!nearest.has(row.number) || distance < nearest.get(row.number)) {
      stages.set(row.number, keys.get(row.key));
      nearest.set(row.number, distance);
    }
  }
  return stages;
}
function resultBefore(bytes, header) {
  const dv = dvOf(bytes);
  for (let count = 0; count <= 80; count++) {
    const start = header - 30 - 8 * count;
    if (start < 0 || bytes[start] !== 1 || bytes[start + 1] !== 0x18 || dv.getUint32(start + 26, true) !== count) continue;
    const home = bytes.subarray(start + 6, start + 10), away = bytes.subarray(start + 10, start + 14);
    const validScore = row => row[0] !== 255 && row.every(value => value === 255 || value < 100);
    if (!validScore(home) || !validScore(away)) continue;
    return { homeScore: home[0], awayScore: away[0], attendance: dv.getUint32(start + 14, true) };
  }
  return null;
}
function parseFixtureChunk(bytes, baseOffset, targetClubId, teamClubMap, stageMap, found) {
  const dv = dvOf(bytes);
  for (let p = 0; p + 40 <= bytes.length; p++) {
    if (bytes[p] !== 0x18) continue;
    const regular = bytes[p + 16] === 255 && bytes[p + 23] === 255;
    const alt = bytes.subarray(p + 33, p + 38).length === 5 && bytes[p + 33] === 255 &&
      bytes[p + 34] === 255 && bytes[p + 35] === 255 && bytes[p + 36] === 255 && bytes[p + 37] === 255 &&
      Math.abs(dv.getUint16(p + 38, true) - dv.getUint16(p + 27, true)) <= 1;
    if (!regular && !alt) continue;
    const date = dateFromPacked(bytes, p + 25);
    if (!date) continue;
    const stageId = dv.getUint32(p + 1, true), fixtureId = dv.getUint32(p + 5, true);
    const homeTeam = dv.getUint32(p + 12, true), awayTeam = dv.getUint32(p + 19, true);
    if (homeTeam >= 500000 || awayTeam >= 500000) continue;
    const homeClubId = teamClubMap.get(homeTeam) ?? null, awayClubId = teamClubMap.get(awayTeam) ?? null;
    if (homeClubId !== targetClubId && awayClubId !== targetClubId) continue;
    const key = fixtureId + '|' + date + '|' + homeTeam + '|' + awayTeam;
    if (found.has(key)) continue;
    found.add(key);
    const result = resultBefore(bytes, p);
    const competitionUid = stageMap.get(stageId) ?? null;
    found.rows.push({
      fixtureId, stageId, competitionUid, date, seasonStart: seasonStartOf(date),
      homeTeam, awayTeam, homeClubId, awayClubId,
      homeScore: result?.homeScore ?? null, awayScore: result?.awayScore ?? null,
      attendance: result?.attendance ?? null
    });
  }
}
function parseFixtures(archive, targetClubId, teamClubMap, stageMap, onProgress) {
  const raw = archive.member('rgman/fix_man.dat');
  const first = findMagic(raw);
  if (first < 0) return [];
  const found = new Set(); found.rows = [];
  let offset = 0, tail = new Uint8Array(0);
  const prefix = raw.subarray(0, first);
  parseFixtureChunk(prefix, 0, targetClubId, teamClubMap, stageMap, found);
  tail = prefix.subarray(Math.max(0, prefix.length - 700)).slice();
  offset = first;
  let blockNumber = 0;
  forEachInnerBlock(raw, block => {
    const combined = concatBytes([tail, block]);
    parseFixtureChunk(combined, offset - tail.length, targetClubId, teamClubMap, stageMap, found);
    tail = combined.subarray(Math.max(0, combined.length - 700)).slice();
    offset += block.length;
    blockNumber++;
    if (blockNumber % 100 === 0) onProgress?.(86 + Math.min(4, blockNumber / 1827 * 4), 'A ler jogos e resultados da carreira…');
  });
  return found.rows.sort((a, b) => a.date.localeCompare(b.date));
}
function parseTransfers(archive, people, targetClubId, teamClubMap, onProgress) {
  const raw = archive.member('transfer_man.dat'), first = findMagic(raw);
  if (first < 0) return [];
  const careerIds = new Set(people.filter(p => p.clubId === targetClubId || p.contractClubId === targetClubId).map(p => p.id));
  if (!careerIds.size) return [];
  const parts = [raw.subarray(0, first)];
  let count = 0;
  forEachInnerBlock(raw, block => { parts.push(block); count++; });
  const stream = concatBytes(parts), dv = dvOf(stream), result = [], seen = new Set();
  const kinds = {1:'Transferência',2:'Troca',3:'Empréstimo',4:'Transferência livre',6:'Compensação',7:'Agente livre',8:'Troca',9:'Dispensa',14:'Formação'};
  for (let p = 0; p + 37 <= stream.length; p++) {
    if (stream[p] !== 6 || stream[p + 5] !== 0 || stream[p + 10] !== 0 || stream[p + 15] !== 0) continue;
    const personId = dv.getUint32(p + 1, true);
    if (!careerIds.has(personId)) continue;
    const toTeam = dv.getUint32(p + 6, true), fromTeam = dv.getUint32(p + 11, true), squad = dv.getUint32(p + 16, true);
    if ([toTeam, fromTeam, squad].some(team => team !== 0xffffffff && team >= 500000)) continue;
    const date = dateFromPacked(stream, p + 33);
    if (!date || stream[p + 32] > 15) continue;
    const kind = stream[p + 32], fee = dv.getUint32(p + 20, true), feeWithAddOns = dv.getUint32(p + 28, true);
    const fromClubId = fromTeam === 0xffffffff ? null : (teamClubMap.get(fromTeam) ?? null);
    const toClubId = toTeam === 0xffffffff ? null : (teamClubMap.get(toTeam) ?? null);
    const dedupe = [personId,date,kind,fromClubId,toClubId,fee,feeWithAddOns].join('|');
    if (seen.has(dedupe)) continue;
    seen.add(dedupe);
    result.push({
      personId, date, kind, type:kinds[kind] || 'Outra operação',
      fromClubId, toClubId, fee:Math.round(fee * 1.166),
      addOns:Math.round(Math.max(0, feeWithAddOns - fee) * 1.166),
      originalFee:fee, originalFeeWithAddOns:feeWithAddOns
    });
  }
  onProgress?.(91, 'A ler transferências dos jogadores da carreira…');
  return result.sort((a,b)=>a.date.localeCompare(b.date));
}
function readStatGroups(ls) {
  if (!ls || ls.length < 12) return [];
  const count = Math.floor((ls.length - 8) / 4), values = new Int32Array(count);
  const dv = dvOf(ls);
  for (let i = 0; i < count; i++) values[i] = dv.getInt32(8 + i * 4, true);
  const ungrouped = values[0], groupIndex = 1 + ungrouped;
  if (ungrouped < 0 || groupIndex >= values.length) return [];
  const groupsCount = values[groupIndex];
  if (groupsCount < 0 || groupsCount > 200000) return [];
  let index = groupIndex + 1;
  const groups = [];
  for (let g = 0; g < groupsCount; g++) {
    if (index >= values.length) return [];
    const n = values[index++];
    if (n < 0 || n > 1000 || index + n > values.length) return [];
    const stored = Array.from(values.subarray(index, index + n));
    groups.push(stored.map((value, k) => k === 0 ? value : value + stored[k - 1]));
    index += n;
  }
  return groups;
}
function parsePlayerSeasonStats(archive, people, targetClubId, teamClubMap, globalGroupCounts, onProgress) {
  const dt = archive.member('player_stats_hist_dt.cmt');
  const ls = archive.member('rgman/player_stats_hist_ls.dat');
  const groups = readStatGroups(ls), counts = globalGroupCounts || new Map();
  const owners = new Map();
  for (const p of people) {
    if (p.clubId !== targetClubId && p.contractClubId !== targetClubId) continue;
    if (Number.isInteger(p.statsGroup) && counts.get(p.statsGroup) === 1) owners.set(p.statsGroup, p);
  }
  const dv = dvOf(dt), out = [], kindNames = ['Amigável','Liga','Taça','Continental','Seleção'];
  for (const [group, player] of owners) {
    for (const offset of groups[group]) {
      const at = 8 + offset;
      if (offset < 0 || offset % 152 !== 0 || at + 152 > dt.length) continue;
      const teamId = dv.getUint32(at + 1, true), clubId = teamClubMap.get(teamId);
      if (clubId !== targetClubId) continue;
      const leagueKey = dv.getUint16(at + 5, true), seasonStart = dv.getUint16(at + 11, true);
      const ratingTotal = dv.getUint16(at + 13, true), minutes = dv.getUint16(at + 15, true);
      const starts = dt[at + 24], substituteAppearances = dt[at + 25], ratedAppearances = dt[at + 26];
      const kind = dt[at + 31];
      if (seasonStart < 1900 || seasonStart > 2200 || kind > 4) continue;
      out.push({
        personId:player.id, teamId, clubId, seasonStart, leagueKey, kind, kindName:kindNames[kind],
        appearances:starts + substituteAppearances, starts, substituteAppearances, minutes,
        goals:dt[at + 27], assists:dt[at + 28], playerOfMatch:dt[at + 29],
        goalsConceded:dt[at + 17], cleanSheets:dt[at + 22], yellowCards:dt[at + 21], redCards:dt[at + 20],
        averageRating:ratedAppearances ? Math.round((ratingTotal / ratedAppearances / 10) * 100) / 100 : null,
        ratedAppearances, ratingTotal
      });
    }
  }
  const aggregate = new Map();
  for (const row of out) {
    const key = [row.personId,row.seasonStart,row.clubId].join('|');
    if (!aggregate.has(key)) aggregate.set(key, {
      personId:row.personId,clubId:row.clubId,seasonStart:row.seasonStart,
      appearances:0,starts:0,substituteAppearances:0,minutes:0,goals:0,assists:0,
      playerOfMatch:0,goalsConceded:0,cleanSheets:0,yellowCards:0,redCards:0,
      ratedAppearances:0,ratingTotal:0,teamIds:[],kindBreakdown:{}
    });
    const a = aggregate.get(key);
    for (const field of ['appearances','starts','substituteAppearances','minutes','goals','assists','playerOfMatch','goalsConceded','cleanSheets','yellowCards','redCards','ratedAppearances','ratingTotal']) a[field] += row[field] || 0;
    if (!a.teamIds.includes(row.teamId)) a.teamIds.push(row.teamId);
    a.kindBreakdown[row.kindName] = {
      ...(a.kindBreakdown[row.kindName] || {appearances:0,goals:0,assists:0,minutes:0}),
      appearances:(a.kindBreakdown[row.kindName]?.appearances || 0) + row.appearances,
      goals:(a.kindBreakdown[row.kindName]?.goals || 0) + row.goals,
      assists:(a.kindBreakdown[row.kindName]?.assists || 0) + row.assists,
      minutes:(a.kindBreakdown[row.kindName]?.minutes || 0) + row.minutes
    };
  }
  onProgress?.(94, 'A ler estatísticas por época…');
  return [...aggregate.values()].map(row => ({
    ...row,
    averageRating:row.ratedAppearances ? Math.round((row.ratingTotal / row.ratedAppearances / 10) * 100) / 100 : null
  }));
}
function parseTrophies(archive, targetClubId, teamClubMap, competitionKeys) {
  const dt = archive.member('comp_history_dt.cmt'), dv = dvOf(dt), out = [], seen = new Set();
  for (let p = 8; p + 55 <= dt.length; p += 55) {
    const key = dv.getUint32(p, true), year = dv.getUint16(p + 4, true), start = dv.getUint16(p + 6, true);
    const winnerTeam = dv.getUint32(p + 8, true), clubId = teamClubMap.get(winnerTeam);
    if (clubId !== targetClubId) continue;
    const wonOn = dateFromPacked(dt, p + 51);
    if (!wonOn) continue;
    const competitionUid = competitionKeys.get(key) ?? key;
    const dedupe = key + '|' + year + '|' + wonOn;
    if (seen.has(dedupe)) continue;
    seen.add(dedupe);
    out.push({competitionUid, competitionKey:key, year, seasonStart:start || (year - 1), wonOn});
  }
  return out.sort((a,b)=>a.wonOn.localeCompare(b.wonOn));
}


const MATCH_PLAYER_OFFSETS = {
  goals:19,shots:40,shotsOnTarget:41,assists:55,clearCutChances:56,dribbles:57,fouls:59,
  yellowCards:62,redCards:63,minuteOff:66,addedTimeOff:68,minuteOn:70,injuryMinute:71,
  bookedMinute:72,sentOffMinute:73,passes:85,passesCompleted:86,keyPasses:87,crosses:88,
  crossesCompleted:89,tackles:91,tacklesWon:92,keyTackles:93,headers:94,headersWon:95,
  keyHeaders:96,interceptions:97,clearances:139,goalsOutsideBox:165,
  mistakesLeadingToGoal:130,goalsConceded:20,blockedShots:42,longShots:43,halfChances:45,
  savesHeld:49,savesParried:50,savesTipped:51,shotsOutsideBox:166
};
function findByteSequence(bytes, sequence, start, end) {
  const limit = Math.min(bytes.length, end ?? bytes.length);
  for (let p = Math.max(0,start||0); p + sequence.length <= limit; p++) {
    let ok = true;
    for (let i=0;i<sequence.length;i++) if (bytes[p+i] !== sequence[i]) {ok=false;break;}
    if (ok) return p;
  }
  return -1;
}
function matchPlayerRecordSize(bytes, at) {
  if (at < 1 || at + 200 > bytes.length) return null;
  let end = at + 195;
  const shots = bytes[at + 194];
  if (shots > 30) return null;
  for (let i=0;i<shots;i++) {
    if (end + 3 > bytes.length) return null;
    const parts = bytes[end + 2];
    if (parts > 20) return null;
    end += 3 + 15 * parts;
  }
  if (end + 5 > bytes.length) return null;
  const items = bytes[end + 3];
  if (items > 30) return null;
  const size = end + 5 + 11 * items - at;
  return size >= 200 && at + size <= bytes.length ? size : null;
}
function parseMatchPlayer(bytes, at, teamId, matchMinutes, playerOfTheMatch) {
  if (at < 1 || at + 200 > bytes.length || bytes[at - 1] !== 2) return null;
  const dv = dvOf(bytes);
  const ratingRaw = dv.getUint16(at + 122, true);
  const distance = dv.getFloat32(at + 126, true), xg = dv.getFloat32(at + 24, true);
  if (!(ratingRaw >= 1 && ratingRaw <= 1000 && Number.isFinite(distance) && distance >= 0 && distance < 25000 &&
        Number.isFinite(xg) && xg >= 0 && xg < 10)) return null;
  const values = {};
  for (const [field,offset] of Object.entries(MATCH_PLAYER_OFFSETS)) values[field] = bytes[at + offset];
  if (['minuteOff','minuteOn','bookedMinute','injuryMinute','sentOffMinute'].some(field=>values[field] > 130)) return null;
  if (values.shotsOnTarget > values.shots || values.passesCompleted > values.passes ||
      values.crossesCompleted > values.crosses || values.tacklesWon > values.tackles ||
      values.headersWon > values.headers) return null;
  const played = distance > 0 || ['goals','assists','shots','passes','crosses','tackles','headers','fouls','interceptions','clearances','minuteOn','minuteOff']
    .some(field=>values[field] > 0);
  if (played && ratingRaw < 100) return null;
  const startSlot = dv.getUint16(at + 7, true), endSlot = dv.getUint16(at + 109, true);
  const startMinute = values.minuteOn;
  const endMinute = values.minuteOff ? values.minuteOff + values.addedTimeOff : matchMinutes;
  const minutesPlayed = played ? Math.max(0,Math.min(matchMinutes,endMinute)-startMinute) : 0;
  const personId = dv.getUint32(at, true);
  return {
    personId,teamId,started:startSlot!==0,minutesPlayed,position:null,
    rating:played ? Math.round((ratingRaw/100)*100)/100 : null,
    goals:values.goals,assists:values.assists,shots:values.shots,shotsOnTarget:values.shotsOnTarget,
    keyPasses:values.keyPasses,tackles:values.tackles,interceptions:values.interceptions,
    passesCompleted:values.passesCompleted,passesAttempted:values.passes,
    yellowCards:values.yellowCards,redCards:values.redCards,ownGoals:0,
    playerOfTheMatch:personId===playerOfTheMatch,
    stats:{...values,xg,distance,shirt:bytes[at+4],startSlot,endSlot,playerOfTheMatch:personId===playerOfTheMatch}
  };
}
function parseMatchPlayers(bytes, first, squad, teamId, matchMinutes, playerOfTheMatch) {
  const players = [];
  let at = first;
  for (let i=0;i<squad;i++) {
    const player = parseMatchPlayer(bytes,at,teamId,matchMinutes,playerOfTheMatch);
    const size = player ? matchPlayerRecordSize(bytes,at) : null;
    if (!player || !size) return null;
    players.push(player);
    at += size;
  }
  return {players,end:at-1};
}
function parseMatchSide(bytes, start, teamId, matchMinutes, playerOfTheMatch) {
  const marker = [2,teamId&255,(teamId>>>8)&255,(teamId>>>16)&255,(teamId>>>24)&255];
  let at = findByteSequence(bytes,marker,start,start+12000);
  while (at >= 0) {
    const squad = bytes[at+5];
    if (squad > 0 && squad <= 60) {
      for (let first=at+6; first<Math.min(at+1200,bytes.length); first++) {
        if (first<14 || bytes[first-14]!==2 || bytes[first-1]!==2) continue;
        const walked = parseMatchPlayers(bytes,first,squad,teamId,matchMinutes,playerOfTheMatch);
        if (walked) return walked;
      }
    }
    at = findByteSequence(bytes,marker,at+1,start+12000);
  }
  return null;
}
function parseMatchReportAt(bytes, p, targetClubId, teamClubMap) {
  if (bytes[p]!==2 || bytes[p+1]!==2 || bytes[p+6]!==2 || bytes[p+11]>31 ||
      bytes[p+12]!==0 || bytes[p+13]>1 || bytes[p+22]!==2 || bytes[p+23]!==2) return null;
  const dv = dvOf(bytes), homeTeam=dv.getUint32(p+2,true), awayTeam=dv.getUint32(p+24,true);
  const homeClubId=teamClubMap.get(homeTeam)??null, awayClubId=teamClubMap.get(awayTeam)??null;
  if (homeClubId!==targetClubId && awayClubId!==targetClubId) return null;
  const head=bytes.subarray(Math.max(0,p-120),p);
  let named=null;
  for (let length=1;length<111;length++) {
    const at=head.length-length-4;
    if (at>=9 && dvOf(head).getUint32(at,true)===length && head[at-9]===2) {named={length,at};break;}
  }
  if (!named) return null;
  const fixtureId=dvOf(head).getUint32(named.at-8,true);
  const stadium=new TextDecoder().decode(head.subarray(named.at+4)).replace(/\0+$/,'').trim() || null;
  const partMarker=[2,homeTeam&255,(homeTeam>>>8)&255,(homeTeam>>>16)&255,(homeTeam>>>24)&255];
  const part=findByteSequence(bytes,partMarker,p+28,p+28+12000);
  if (part<0) return null;
  const pomAt=part-14;
  let playerOfTheMatch=null,matchMinutes=90;
  if (pomAt>=0 && bytes[pomAt]===2) {
    playerOfTheMatch=dv.getUint32(pomAt+1,true);
    const minutes=dv.getUint16(pomAt+7,true);
    if (minutes>=45 && minutes<=130) matchMinutes=minutes;
  }
  const home=parseMatchSide(bytes,p+28,homeTeam,matchMinutes,playerOfTheMatch);
  if (!home) return null;
  const away=parseMatchSide(bytes,home.end,awayTeam,matchMinutes,playerOfTheMatch);
  if (!away) return null;
  const players=[...home.players,...away.players].filter(player=>teamClubMap.get(player.teamId)===targetClubId);
  return {fixtureId,homeTeam,awayTeam,homeClubId,awayClubId,stadium,playerOfTheMatch,minutes:matchMinutes,players};
}
function parseMatchReports(archive, targetClubId, teamClubMap, onProgress) {
  const raw=archive.member('match_stats_cfg.dat'), reports=new Map();
  let tail=new Uint8Array(0), offset=0, processed=0, blockNumber=0;
  const lookahead=30000, tailSize=lookahead+120;
  const scan=(bytes,base,safeEnd)=>{
    const start=Math.max(0,processed-base);
    for(let p=start;p+28<=safeEnd;p++){
      if(bytes[p]!==2 || bytes[p+1]!==2) continue;
      const report=parseMatchReportAt(bytes,p,targetClubId,teamClubMap);
      if(report && !reports.has(report.fixtureId)) reports.set(report.fixtureId,report);
    }
    processed=base+safeEnd;
  };
  forEachInnerBlock(raw,block=>{
    const combined=concatBytes([tail,block]),base=offset-tail.length;
    scan(combined,base,Math.max(0,combined.length-lookahead));
    tail=combined.subarray(Math.max(0,combined.length-tailSize)).slice();
    offset+=block.length;
    blockNumber++;
    if(blockNumber%200===0) onProgress?.(93+Math.min(1,blockNumber/4077),'A ler estatísticas detalhadas dos jogos…');
  });
  const finalBase=offset-tail.length;
  scan(tail,finalBase,tail.length);
  return [...reports.values()];
}

function parseManagerSpellsForClub(archive, rawPeople, managerName, targetClubId, teams, matches, gameDate) {
  const normalise = value => String(value || '').replace(/\bGOAT\b/ig,'').normalize('NFD')
    .replace(/[\u0300-\u036f]/g,'').toLowerCase().replace(/[^a-z0-9]/g,'');
  const wanted = normalise(managerName);
  if (!wanted) return {managerPersonId:null,spells:[],warning:'Para importar o percurso do treinador, é necessário identificar o nome exacto do treinador dentro do save.'};
  const candidates = rawPeople.filter(p => p.id >= 0 &&
    (normalise(p.name) === wanted || normalise(p.fullName) === wanted));
  if (candidates.length !== 1) return {managerPersonId:null,spells:[],warning:
    candidates.length ? 'O nome do treinador corresponde a mais do que uma pessoa no save.' :
      'O nome do treinador da carreira não foi encontrado nos registos do save.'};
  const manager = candidates[0];
  const dt = archive.member('tc_manager_history_dt.cmt');
  const ls = archive.member('tc_manager_history_ls.dat');
  const groups = readStatGroups(ls), dv = dvOf(dt);
  const seniorTeams = teams.filter(t=>t.club===targetClubId&&t.type===100).map(t=>t.ordinal+1);
  if (!seniorTeams.length) return {managerPersonId:manager.id,spells:[],warning:'Não foi possível identificar a equipa principal para validar o histórico do treinador.'};
  const validGroups = [];
  for (let index=0; index<groups.length; index++) {
    const spells = [];
    for (const offset of groups[index]) {
      const at = 8 + offset;
      if (offset < 0 || offset % 31 !== 0 || at + 31 > dt.length) continue;
      const personId = dv.getUint32(at,true);
      const startedOn = dateFromPacked(dt,at+4);
      const endedOn = dateFromPacked(dt,at+8);
      const won = dv.getUint16(at+20,true), drawn = dv.getUint16(at+22,true), lost = dv.getUint16(at+24,true);
      spells.push({personId,startedOn,endedOn,won,drawn,lost,reason:dt[at+26],leagueWins:dt[at+27],cupWins:dt[at+28]});
    }
    if (!spells.some(spell=>spell.personId===manager.id)) continue;
    const compared = spells.filter(spell=>spell.startedOn&&spell.endedOn&&spell.won+spell.drawn+spell.lost>=4)
      .sort((a,b)=>(b.won+b.drawn+b.lost)-(a.won+a.drawn+a.lost)).slice(0,5);
    if (!compared.length) continue;
    for (const teamId of seniorTeams) {
      let difference=0,games=0;
      for (const spell of compared) {
        let wins=0,draws=0,losses=0;
        for (const match of matches) {
          if (match.homeTeam!==teamId&&match.awayTeam!==teamId) continue;
          if (match.homeScore===null || match.awayScore===null) continue;
          if (match.date<spell.startedOn || match.date>(spell.endedOn || gameDate)) continue;
          const teamWon = match.homeTeam===teamId ? match.homeScore>match.awayScore : match.awayScore>match.homeScore;
          const level = match.homeScore===match.awayScore;
          if (level) draws++;
          else if (teamWon) wins++;
          else losses++;
        }
        difference += Math.abs(wins-spell.won)+Math.abs(draws-spell.drawn)+Math.abs(losses-spell.lost);
        games += spell.won+spell.drawn+spell.lost;
      }
      if (games >= 10 && difference/games <= 0.12) validGroups.push({index,teamId,spells,score:difference/games,games});
    }
  }
  validGroups.sort((a,b)=>a.score-b.score||b.games-a.games);
  if (!validGroups.length) return {managerPersonId:manager.id,spells:[],warning:'O histórico do treinador existe, mas não foi possível associá-lo com segurança ao Sporting.'};
  const best = validGroups[0];
  const managerSpells = best.spells.filter(spell=>spell.personId===manager.id&&spell.startedOn).map(spell=>({
    personId:manager.id,clubId:targetClubId,teamId:best.teamId,startedOn:spell.startedOn,
    endedOn:spell.endedOn,won:spell.won,drawn:spell.drawn,lost:spell.lost,
    reason:spell.reason,leagueWins:spell.leagueWins,cupWins:spell.cupWins
  }));
  return {managerPersonId:manager.id,spells:managerSpells,warning:null};
}

function buildHistory(archive, gameDb, people, rawPeople, clubs, teams, gameDate, clubName, managerName, globalGroupCounts, onProgress) {
  const normalise = value => String(value || '').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase().replace(/[^a-z0-9]/g,'');
  const target = normalise(clubName);
  const managedClub = clubs.find(c => normalise(c.shortName) === target || normalise(c.name) === target ||
    (target === 'sporting' && normalise(c.shortName).startsWith('sporting')));
  if (!managedClub) return {managedClubId:null,clubs:[],competitions:[],seasons:[],matches:[],transfers:[],playerSeasonRecords:[],trophies:[],managerPersonId:null,managerSpells:[],warnings:['Não foi possível associar o clube da carreira aos clubes do save; o histórico não foi importado.']};
  const teamClubMap = new Map(teams.filter(t=>t.club!==null).map(t=>[t.ordinal+1,t.club]));
  const competitionKeys = readCompetitionKeys(gameDb), stageMap = readCompetitionStages(gameDb, competitionKeys);
  onProgress?.(84, 'A preparar o histórico da carreira…');
  const matches = parseFixtures(archive, managedClub.id, teamClubMap, stageMap, onProgress);
  const transfers = parseTransfers(archive, people, managedClub.id, teamClubMap, onProgress);
  const playerSeasonRecords = parsePlayerSeasonStats(archive, people, managedClub.id, teamClubMap, globalGroupCounts, onProgress);
  const trophies = parseTrophies(archive, managedClub.id, teamClubMap, competitionKeys);
  const managerHistory = parseManagerSpellsForClub(archive, rawPeople, managerName, managedClub.id, teams, matches, gameDate);
  const competitionMap = new Map();
  const addCompetition = (uid, rawId) => {
    if (!uid) return;
    if (!competitionMap.has(uid)) competitionMap.set(uid,{uid,name:'Competição FM24 '+uid,rawIds:[]});
    if (rawId !== undefined && !competitionMap.get(uid).rawIds.includes(rawId)) competitionMap.get(uid).rawIds.push(rawId);
  };
  for (const match of matches) addCompetition(match.competitionUid || match.stageId, match.stageId);
  for (const trophy of trophies) addCompetition(trophy.competitionUid, trophy.competitionKey);
  const seasonStarts = new Set();
  for (const match of matches) seasonStarts.add(match.seasonStart);
  for (const stat of playerSeasonRecords) seasonStarts.add(stat.seasonStart);
  for (const trophy of trophies) seasonStarts.add(trophy.seasonStart);
  if (gameDate) seasonStarts.add(seasonStartOf(gameDate));
  const seasons = [...seasonStarts].filter(y=>y>=1900&&y<=2200).sort((a,b)=>a-b).map(year=>({
    label:year+'/'+String(year+1).slice(-2),startDate:year+'-07-01',endDate:(year+1)+'-06-30',
    isCurrent:!!gameDate && seasonStartOf(gameDate)===year
  }));
  const clubIds = new Set([managedClub.id]);
  for (const match of matches) { clubIds.add(match.homeClubId); clubIds.add(match.awayClubId); }
  for (const transfer of transfers) { if(transfer.fromClubId!==null)clubIds.add(transfer.fromClubId);if(transfer.toClubId!==null)clubIds.add(transfer.toClubId); }
  const clubMap = new Map(clubs.map(c=>[c.id,c]));
  const historyClubs = [...clubIds].filter(id=>id!==null&&clubMap.has(id)).map(id=>{
    const c=clubMap.get(id);return {fm24ClubId:c.id,name:c.name,shortName:c.shortName,country:NATIONS[String(c.nation)]||null};
  });
  return {managedClubId:managedClub.id,clubs:historyClubs,competitions:[...competitionMap.values()],seasons,matches,transfers,playerSeasonRecords,trophies,managerPersonId:managerHistory.managerPersonId,managerSpells:managerHistory.spells,warnings:managerHistory.warning?[managerHistory.warning]:[]};
}

/* ---------- orquestrador: parseSave ---------- */
function dateOf(year, day) {
  const date = new Date(Date.UTC(year, 0, day));
  return date.toISOString().slice(0, 10);
}
async function parseSave(rawBytes, onProgress = () => {}, options = {}) {
  onProgress(2, 'A ler índice do save…'); await tick();
  const a = new SaveArchive(rawBytes);
  const info = a.member('game_info.dat');
  const formatVersion = utf8Slice(info, 12, 20);
  if (formatVersion !== '24.3.0+0')
    throw new SaveError('UNSUPPORTED_VERSION', `Formato de save ${formatVersion} não suportado. É necessário um save FM24 24.3.`);
  onProgress(10, 'A ler base de dados de jogadores…'); await tick();
  const b = a.member('game_db.dat');
  const dv = dvOf(b);
  if (b.length < 40) throw new SaveError('TRUNCATED', 'O cabeçalho da base de dados está incompleto.');
  const day0 = dv.getUint16(36, true) & 511, year = dv.getUint16(38, true);
  if (day0 < 1 || day0 > 366 || year < 2020 || year > 2300)
    throw new SaveError('UNSUPPORTED_DATE', 'Não foi possível ler a data do jogo.');
  const gameDate = dateOf(year, day0);
  onProgress(22, 'A resolver nomes de jogadores…'); await tick();
  const names = readNames(b, dv);
  onProgress(35, 'A ler registos de jogadores…'); await tick();
  const people = await readPeople(b, dv, names, (frac) => onProgress(35 + 17 * frac, 'A ler registos de jogadores…'));
  onProgress(52, 'A ler capacidade e atributos…'); await tick();
  const blocks = await readAbilities(b, dv, names.end, (frac) => onProgress(52 + 16 * frac, 'A ler capacidade e atributos…'));
  const { linked, ambiguous, unbound } = linkAbilities(people, blocks);
  onProgress(68, 'A resolver clubes e plantéis…'); await tick();
  const clubs = readClubs(b, dv, names.start);
  const clubMap = new Map(clubs.map((c) => [c.id, c]));
  const teams = readTeams(b, dv, clubs, names.start, new Set(people.filter((p) => p.id >= 0).map((p) => p.id)));
  const teamMap = new Map(teams.map((t) => [t.ordinal + 1, t]));
  const squads = new Map();
  for (const t of teams) {
    if (t.club === null) continue;
    for (const id of t.members) {
      if (!squads.has(id) || t.type === 100) squads.set(id, t.club);
    }
  }
  onProgress(82, 'A construir perfis de jogadores…'); await tick();
  const players = linked.map(({ person: p, ability: ab }) => {
    const clubId = teamMap.get(ab.team)?.club ?? squads.get(p.id) ?? null;
    // FM24 contract rows: [person id][team][00 x4][weekly wage][01 ?? 00].
    // The first positive-wage row identifies the owning club; loan rows at
    // the destination club generally have zero wage.
    const contractWindow = b.subarray(Math.max(0, p.offset - 4000), p.offset);
    let contractClubId = null;
    const personIdBytes = new Uint8Array(4);
    new DataView(personIdBytes.buffer).setUint32(0, p.id, true);
    for (let row = 0; row + 19 <= contractWindow.length; row++) {
      if (contractWindow[row] !== personIdBytes[0] || contractWindow[row+1] !== personIdBytes[1] ||
          contractWindow[row+2] !== personIdBytes[2] || contractWindow[row+3] !== personIdBytes[3]) continue;
      if (contractWindow[row+8] || contractWindow[row+9] || contractWindow[row+10] || contractWindow[row+11] ||
          contractWindow[row+16] !== 1 || contractWindow[row+18] !== 0) continue;
      const wage = new DataView(contractWindow.buffer, contractWindow.byteOffset, contractWindow.byteLength).getUint32(row+12, true);
      const team = new DataView(contractWindow.buffer, contractWindow.byteOffset, contractWindow.byteLength).getUint32(row+4, true);
      if (wage > 0 && teamMap.get(team)?.club != null) { contractClubId = teamMap.get(team).club; break; }
    }
    const loanedOut = contractClubId !== null && clubId !== null && contractClubId !== clubId;
    const raw = [...ab.raw, ...p.personality];
    const attributes = {};
    for (const x of ATTRIBUTES) attributes[x.key] = x.scale === 5 ? displayAttribute(raw[x.index]) : raw[x.index];
    const birthDate = dateOf(p.birthYear, p.birthDay);
    const age = year - p.birthYear - (gameDate.slice(5) < birthDate.slice(5) ? 1 : 0);
    return {
      id: p.id, uid: p.uid, name: p.name, fullName: p.fullName, age, birthDate,
      nationId: p.nation, otherNationIds: p.otherNations, clubId,
      club: clubId === null ? null : (clubMap.get(clubId)?.shortName ?? null),
      clubFullName: clubId === null ? null : (clubMap.get(clubId)?.name ?? null),
      contractClubId,
      contractClub: contractClubId === null ? null : (clubMap.get(contractClubId)?.shortName ?? null),
      contractClubFullName: contractClubId === null ? null : (clubMap.get(contractClubId)?.name ?? null),
      loanedOut,
      loanDestination: loanedOut ? (clubId === null ? null : (clubMap.get(clubId)?.shortName ?? null)) : null,
      ca: ab.ca, pa: ab.pa,
      positions: POSITIONS.filter((_, i) => ab.positions[i] >= 15),
      positionRatings: ab.positions,
      attributes, rawAttributes: raw,
      statsGroup: p.end >= 40 ? dv.getUint32(p.end - 40, true) : null,
    };
  });
  if (!players.length) throw new SaveError('NO_PLAYERS', 'Não foram encontrados registos de jogadores suportados neste save.');
  if (new Set(players.map((p) => p.id)).size !== players.length)
    throw new SaveError('AMBIGUOUS_IDENTITIES', 'As identidades dos jogadores não validaram.');
  onProgress(82, 'A preparar dados históricos da carreira…'); await tick();
  const teamClubMap = teams.filter((t) => t.club !== null).map((t) => ({ teamId: t.ordinal + 1, clubId: t.club }));
  const statsGroupCounts = new Map();
  for (const person of people) {
    if (person.end >= 40) {
      const group = dv.getUint32(person.end - 40, true);
      statsGroupCounts.set(group, (statsGroupCounts.get(group) || 0) + 1);
    }
  }
  const history = buildHistory(a, b, players, people, clubs, teams, gameDate, options.clubName || '', options.managerName || '', statsGroupCounts, onProgress);
  onProgress(96, 'A preparar a lista de jogadores…');
  const warnings = [...history.warnings];
  if (ambiguous + unbound)
    warnings.push(`${ambiguous + unbound} registos ambíguos foram excluídos por segurança.`);
  return { name: a.name, formatVersion, gameDate, players, clubs, teamClubMap, history, warnings };
}

/* ---------- mapa de nações (id -> nome) ---------- */
const NATIONS = {"0":"Algeria","1":"Angola","2":"Benin","3":"Botswana","4":"Burkina Faso","5":"Burundi","6":"Cameroon","7":"Cape Verde","8":"Central African Republic","9":"Chad","10":"Djibouti","11":"Egypt","12":"Equatorial Guinea","13":"Ethiopia","14":"Gabon","15":"Gambia","16":"Ghana","17":"Guinea","18":"Guinea-Bissau","19":"Ivory Coast","20":"Kenya","21":"Lesotho","22":"Liberia","23":"Libya","24":"Madagascar","25":"Malawi","26":"Mali","27":"Mauritania","28":"Mauritius","29":"Morocco","30":"Mozambique","31":"Namibia","32":"Niger","33":"Nigeria","34":"Rwanda","35":"São Tomé and Príncipe","36":"Senegal","37":"Seychelles","38":"Sierra Leone","39":"Somalia","40":"South Africa","41":"Sudan","42":"Eswatini","43":"Tanzania","44":"Congo","45":"Togo","46":"Tunisia","47":"Uganda","48":"DR Congo","49":"Zambia","50":"Zimbabwe","51":"Afghanistan","52":"Bahrain","53":"Bangladesh","54":"Brunei","55":"China","56":"Hong Kong","57":"India","58":"Indonesia","59":"Iran","60":"Iraq","61":"Japan","62":"Jordan","63":"Cambodia","64":"Kazakhstan","65":"Kuwait","66":"Kyrgyzstan","67":"Laos","68":"Lebanon","69":"Macau","70":"Malaysia","71":"Maldives","72":"Myanmar","73":"Nepal","74":"North Korea","75":"Oman","76":"Pakistan","77":"Qatar","78":"Saudi Arabia","79":"Singapore","80":"South Korea","81":"Sri Lanka","82":"Syria","83":"Chinese Taipei","84":"Tajikistan","85":"Thailand","86":"Philippines","87":"Turkmenistan","88":"United Arab Emirates","89":"Uzbekistan","90":"Vietnam","91":"Yemen","92":"Antigua and Barbuda","93":"Aruba","94":"Barbados","95":"Belize","96":"Bermuda","97":"Canada","98":"Cayman Islands","99":"Costa Rica","100":"Cuba","101":"Dominica","102":"El Salvador","103":"Grenada","104":"Guatemala","105":"Guyana","106":"Haiti","107":"Honduras","108":"Jamaica","109":"Mexico","110":"Curaçao","111":"Nicaragua","112":"Panama","113":"Puerto Rico","114":"Saint Lucia","115":"Saint Kitts and Nevis","116":"Saint Vincent and the Grenadines","117":"Suriname","118":"Bahamas","119":"Trinidad and Tobago","120":"United States","126":"Albania","127":"Andorra","128":"Armenia","129":"Austria","130":"Azerbaijan","131":"Belgium","132":"Belarus","133":"Bosnia and Herzegovina","134":"Bulgaria","135":"Croatia","136":"Cyprus","137":"Czech Republic","138":"Denmark","139":"England","140":"Estonia","141":"Faroe Islands","142":"Finland","143":"France","144":"Georgia","145":"Germany","146":"Greece","147":"Hungary","148":"Iceland","149":"Israel","150":"Italy","151":"Latvia","152":"Liechtenstein","153":"Lithuania","154":"Luxembourg","155":"North Macedonia","156":"Malta","157":"Moldova","158":"Netherlands","159":"Northern Ireland","160":"Norway","161":"Poland","162":"Portugal","163":"Republic of Ireland","164":"Romania","165":"Russia","166":"San Marino","167":"Scotland","168":"Slovakia","169":"Slovenia","170":"Spain","171":"Sweden","172":"Switzerland","173":"Turkey","174":"Ukraine","175":"Wales","176":"Serbia","177":"Australia","178":"Cook Islands","179":"Fiji","180":"New Zealand","181":"Papua New Guinea","182":"Solomon Islands","183":"Tahiti","184":"Tonga","185":"Vanuatu","186":"Samoa","187":"Argentina","188":"Bolivia","189":"Brazil","190":"Chile","191":"Colombia","192":"Ecuador","193":"Paraguay","194":"Peru","195":"Uruguay","196":"Venezuela","197":"Palestine","201":"American Samoa","202":"Mongolia","203":"Guam","204":"Eritrea","205":"Anguilla","206":"British Virgin Islands","207":"Montserrat","208":"US Virgin Islands","209":"Turks and Caicos Islands","210":"New Caledonia","211":"Bhutan","212":"Dominican Republic","215":"Kiribati","216":"Gibraltar","217":"Bonaire","218":"Crimea","219":"Kosovo","225":"French Guiana","226":"Guadeloupe","227":"Martinique","228":"Sint Maarten","229":"Saint Martin","230":"Réunion","231":"Mayotte","232":"Wallis and Futuna","233":"Saint Pierre and Miquelon","234":"Comoros","236":"Timor-Leste","239":"Zanzibar","240":"South Sudan","242":"Micronesia","243":"Northern Mariana Islands","244":"Tuvalu","247":"Montenegro","249":"Saint Barthélemy"};

const NATION_CONTINENT = {"0":"africa","1":"africa","2":"africa","3":"africa","4":"africa","5":"africa","6":"africa","7":"africa","8":"africa","9":"africa","10":"africa","11":"africa","12":"africa","13":"africa","14":"africa","15":"africa","16":"africa","17":"africa","18":"africa","19":"africa","20":"africa","21":"africa","22":"africa","23":"africa","24":"africa","25":"africa","26":"africa","27":"africa","28":"africa","29":"africa","30":"africa","31":"africa","32":"africa","33":"africa","34":"africa","35":"africa","36":"africa","37":"africa","38":"africa","39":"africa","40":"africa","41":"africa","42":"africa","43":"africa","44":"africa","45":"africa","46":"africa","47":"africa","48":"africa","49":"africa","50":"africa","51":"asia","52":"asia","53":"asia","54":"asia","55":"asia","56":"asia","57":"asia","58":"asia","59":"asia","60":"asia","61":"asia","62":"asia","63":"asia","64":"asia","65":"asia","66":"asia","67":"asia","68":"asia","69":"asia","70":"asia","71":"asia","72":"asia","73":"asia","74":"asia","75":"asia","76":"asia","77":"asia","78":"asia","79":"asia","80":"asia","81":"asia","82":"asia","83":"asia","84":"asia","85":"asia","86":"asia","87":"asia","88":"asia","89":"asia","90":"asia","91":"asia","92":"norte","93":"norte","94":"norte","95":"norte","96":"norte","97":"norte","98":"norte","99":"norte","100":"norte","101":"norte","102":"norte","103":"norte","104":"norte","105":"norte","106":"norte","107":"norte","108":"norte","109":"norte","110":"norte","111":"norte","112":"norte","113":"norte","114":"norte","115":"norte","116":"norte","117":"norte","118":"norte","119":"norte","120":"norte","126":"europa","127":"europa","128":"europa","129":"europa","130":"europa","131":"europa","132":"europa","133":"europa","134":"europa","135":"europa","136":"europa","137":"europa","138":"europa","139":"europa","140":"europa","141":"europa","142":"europa","143":"europa","144":"europa","145":"europa","146":"europa","147":"europa","148":"europa","149":"europa","150":"europa","151":"europa","152":"europa","153":"europa","154":"europa","155":"europa","156":"europa","157":"europa","158":"europa","159":"europa","160":"europa","161":"europa","162":"europa","163":"europa","164":"europa","165":"europa","166":"europa","167":"europa","168":"europa","169":"europa","170":"europa","171":"europa","172":"europa","173":"europa","174":"europa","175":"europa","176":"europa","177":"oceania","178":"oceania","179":"oceania","180":"oceania","181":"oceania","182":"oceania","183":"oceania","184":"oceania","185":"oceania","186":"oceania","187":"sul","188":"sul","189":"sul","190":"sul","191":"sul","192":"sul","193":"sul","194":"sul","195":"sul","196":"sul","197":"asia","201":"oceania","202":"asia","203":"oceania","204":"africa","205":"norte","206":"norte","207":"norte","208":"norte","209":"norte","210":"oceania","211":"asia","212":"norte","215":"oceania","216":"europa","217":"norte","218":"europa","219":"europa","225":"sul","226":"norte","227":"norte","228":"norte","229":"norte","230":"africa","231":"africa","232":"oceania","233":"norte","234":"africa","236":"asia","239":"africa","240":"africa","242":"oceania","243":"oceania","244":"oceania","247":"europa","249":"norte"};
const CONTINENT_LABEL = { europa: 'Europa', sul: 'América do Sul', norte: 'América do Norte', africa: 'África', asia: 'Ásia', oceania: 'Oceania' };
const CONTINENT_ORDER = ['europa', 'sul', 'norte', 'africa', 'asia', 'oceania'];

/* ---------- catálogo de roles/duties FM24 (85 combinações)
   Fonte dos pesos de atributos: Squad Analyzer FM2024 (comunidade),
   modelo 2/1 (chave/preferível), replicado do projeto original. ---------- */
const ROLES = [{"id":"gk-defend","role":"gk","name":"Goalkeeper","group":"Goalkeepers","duty":"defend","k":["concentration","positioning","agility","aerialReach","commandOfArea","communication","handling","kicking","reflexes"],"p":["anticipation","decisions","oneOnOnes","throwing"]},{"id":"sk-defend","role":"sk","name":"Sweeper Keeper","group":"Goalkeepers","duty":"defend","k":["anticipation","concentration","positioning","agility","commandOfArea","kicking","oneOnOnes","reflexes"],"p":["firstTouch","passing","composure","decisions","vision","acceleration","aerialReach","communication","handling","rushingOut","throwing"]},{"id":"sk-support","role":"sk","name":"Sweeper Keeper","group":"Goalkeepers","duty":"support","k":["anticipation","composure","concentration","positioning","agility","commandOfArea","kicking","oneOnOnes","reflexes","rushingOut"],"p":["firstTouch","passing","decisions","vision","acceleration","aerialReach","communication","handling","throwing"]},{"id":"sk-attack","role":"sk","name":"Sweeper Keeper","group":"Goalkeepers","duty":"attack","k":["anticipation","composure","concentration","positioning","agility","commandOfArea","kicking","oneOnOnes","reflexes","rushingOut"],"p":["firstTouch","passing","decisions","vision","acceleration","aerialReach","communication","eccentricity","handling","throwing"]},{"id":"cd-defend","role":"cd","name":"Central Defender","group":"Central defenders","duty":"defend","k":["heading","marking","tackling","positioning","jumpingReach","strength"],"p":["aggression","anticipation","bravery","composure","concentration","decisions","pace"]},{"id":"cd-stopper","role":"cd","name":"Central Defender","group":"Central defenders","duty":"stopper","k":["heading","tackling","aggression","bravery","decisions","positioning","jumpingReach","strength"],"p":["marking","anticipation","composure","concentration"]},{"id":"cd-cover","role":"cd","name":"Central Defender","group":"Central defenders","duty":"cover","k":["marking","tackling","anticipation","concentration","decisions","positioning","pace"],"p":["heading","bravery","composure","jumpingReach","strength"]},{"id":"ncb-defend","role":"ncb","name":"No-Nonsense Centre-Back","group":"Central defenders","duty":"defend","k":["heading","marking","tackling","positioning","jumpingReach","strength"],"p":["aggression","anticipation","bravery","concentration","pace"]},{"id":"ncb-stopper","role":"ncb","name":"No-Nonsense Centre-Back","group":"Central defenders","duty":"stopper","k":["heading","tackling","aggression","bravery","positioning","jumpingReach","strength"],"p":["marking","anticipation","concentration"]},{"id":"ncb-cover","role":"ncb","name":"No-Nonsense Centre-Back","group":"Central defenders","duty":"cover","k":["marking","tackling","anticipation","concentration","positioning","pace"],"p":["heading","bravery","jumpingReach","strength"]},{"id":"bpd-defend","role":"bpd","name":"Ball-Playing Defender","group":"Central defenders","duty":"defend","k":["heading","marking","passing","tackling","composure","positioning","jumpingReach","strength"],"p":["firstTouch","technique","aggression","anticipation","bravery","concentration","decisions","vision","pace"]},{"id":"bpd-stopper","role":"bpd","name":"Ball-Playing Defender","group":"Central defenders","duty":"stopper","k":["heading","passing","tackling","aggression","bravery","composure","decisions","positioning","jumpingReach","strength"],"p":["firstTouch","marking","technique","anticipation","concentration","vision"]},{"id":"bpd-cover","role":"bpd","name":"Ball-Playing Defender","group":"Central defenders","duty":"cover","k":["marking","passing","tackling","anticipation","composure","concentration","decisions","positioning","pace"],"p":["firstTouch","heading","technique","bravery","vision","jumpingReach","strength"]},{"id":"lib-defend","role":"lib","name":"Libero","group":"Central defenders","duty":"defend","k":["firstTouch","heading","marking","passing","tackling","technique","composure","decisions","positioning","teamwork","jumpingReach","strength"],"p":["anticipation","bravery","concentration","pace","stamina"]},{"id":"lib-support","role":"lib","name":"Libero","group":"Central defenders","duty":"support","k":["firstTouch","heading","marking","passing","tackling","technique","composure","decisions","positioning","teamwork","jumpingReach","strength"],"p":["dribbling","anticipation","bravery","concentration","vision","pace","stamina"]},{"id":"wcb-defend","role":"wcb","name":"Wide Centre-Back","group":"Central defenders","duty":"defend","k":["heading","marking","tackling","positioning","jumpingReach","strength"],"p":["dribbling","firstTouch","passing","technique","aggression","anticipation","bravery","composure","concentration","decisions","workRate","agility","pace"]},{"id":"wcb-support","role":"wcb","name":"Wide Centre-Back","group":"Central defenders","duty":"support","k":["dribbling","heading","marking","tackling","positioning","jumpingReach","pace","strength"],"p":["crossing","firstTouch","passing","technique","aggression","anticipation","bravery","composure","concentration","decisions","offTheBall","workRate","agility","stamina"]},{"id":"wcb-attack","role":"wcb","name":"Wide Centre-Back","group":"Central defenders","duty":"attack","k":["crossing","dribbling","heading","marking","tackling","offTheBall","jumpingReach","pace","stamina","strength"],"p":["firstTouch","passing","technique","aggression","anticipation","bravery","composure","concentration","decisions","positioning","workRate","agility"]},{"id":"nfb-defend","role":"nfb","name":"No-Nonsense Full-Back","group":"Full-backs and wing-backs","duty":"defend","k":["marking","tackling","anticipation","positioning","strength"],"p":["heading","aggression","bravery","concentration","teamwork"]},{"id":"fb-defend","role":"fb","name":"Full-Back","group":"Full-backs and wing-backs","duty":"defend","k":["marking","tackling","anticipation","concentration","positioning"],"p":["crossing","passing","decisions","teamwork","workRate","pace","stamina"]},{"id":"fb-support","role":"fb","name":"Full-Back","group":"Full-backs and wing-backs","duty":"support","k":["marking","tackling","anticipation","concentration","positioning","teamwork"],"p":["crossing","dribbling","passing","technique","decisions","workRate","pace","stamina"]},{"id":"fb-attack","role":"fb","name":"Full-Back","group":"Full-backs and wing-backs","duty":"attack","k":["crossing","marking","tackling","anticipation","positioning","teamwork"],"p":["dribbling","firstTouch","passing","technique","concentration","decisions","offTheBall","workRate","agility","pace","stamina"]},{"id":"ifb-defend","role":"ifb","name":"Inverted Full-Back","group":"Full-backs and wing-backs","duty":"defend","k":["heading","marking","tackling","positioning","strength"],"p":["dribbling","firstTouch","passing","technique","aggression","anticipation","bravery","composure","concentration","decisions","workRate","agility","jumpingReach","pace"]},{"id":"wb-defend","role":"wb","name":"Wing-Back","group":"Full-backs and wing-backs","duty":"defend","k":["marking","tackling","anticipation","positioning","teamwork","workRate","acceleration","stamina"],"p":["crossing","dribbling","firstTouch","passing","technique","concentration","decisions","offTheBall","agility","balance","pace"]},{"id":"wb-support","role":"wb","name":"Wing-Back","group":"Full-backs and wing-backs","duty":"support","k":["crossing","dribbling","marking","tackling","offTheBall","teamwork","workRate","acceleration","stamina"],"p":["firstTouch","passing","technique","anticipation","concentration","decisions","positioning","agility","balance","pace"]},{"id":"wb-attack","role":"wb","name":"Wing-Back","group":"Full-backs and wing-backs","duty":"attack","k":["crossing","dribbling","tackling","technique","offTheBall","teamwork","workRate","acceleration","pace","stamina"],"p":["firstTouch","marking","passing","anticipation","concentration","decisions","flair","positioning","agility","balance"]},{"id":"cwb-support","role":"cwb","name":"Complete Wing-Back","group":"Full-backs and wing-backs","duty":"support","k":["crossing","dribbling","technique","offTheBall","teamwork","workRate","acceleration","stamina"],"p":["firstTouch","marking","passing","tackling","anticipation","decisions","flair","positioning","agility","balance","pace"]},{"id":"cwb-attack","role":"cwb","name":"Complete Wing-Back","group":"Full-backs and wing-backs","duty":"attack","k":["crossing","dribbling","technique","flair","offTheBall","teamwork","workRate","acceleration","stamina"],"p":["firstTouch","marking","passing","tackling","anticipation","decisions","positioning","agility","balance","pace"]},{"id":"iwb-defend","role":"iwb","name":"Inverted Wing-Back","group":"Full-backs and wing-backs","duty":"defend","k":["passing","tackling","anticipation","decisions","positioning","teamwork"],"p":["firstTouch","marking","technique","composure","concentration","offTheBall","workRate","acceleration","agility","stamina"]},{"id":"iwb-support","role":"iwb","name":"Inverted Wing-Back","group":"Full-backs and wing-backs","duty":"support","k":["firstTouch","passing","tackling","composure","decisions","teamwork"],"p":["marking","technique","anticipation","concentration","offTheBall","positioning","vision","workRate","acceleration","agility","stamina"]},{"id":"iwb-attack","role":"iwb","name":"Inverted Wing-Back","group":"Full-backs and wing-backs","duty":"attack","k":["firstTouch","passing","tackling","technique","composure","decisions","offTheBall","teamwork","vision","acceleration"],"p":["crossing","dribbling","longShots","marking","anticipation","concentration","flair","positioning","workRate","agility","pace","stamina"]},{"id":"ap-support","role":"ap","name":"Advanced Playmaker","group":"Central and defensive midfielders","duty":"support","k":["firstTouch","passing","technique","composure","decisions","offTheBall","teamwork","vision"],"p":["dribbling","anticipation","flair","agility"]},{"id":"ap-attack","role":"ap","name":"Advanced Playmaker","group":"Central and defensive midfielders","duty":"attack","k":["firstTouch","passing","technique","composure","decisions","offTheBall","teamwork","vision"],"p":["dribbling","anticipation","flair","acceleration","agility"]},{"id":"anchor-defend","role":"anchor","name":"Anchor","group":"Central and defensive midfielders","duty":"defend","k":["marking","tackling","anticipation","concentration","decisions","positioning"],"p":["composure","teamwork","strength"]},{"id":"am-support","role":"am","name":"Attacking Midfielder","group":"Attacking midfielders and forwards","duty":"support","k":["firstTouch","longShots","passing","technique","anticipation","decisions","flair","offTheBall"],"p":["dribbling","composure","vision","agility"]},{"id":"am-attack","role":"am","name":"Attacking Midfielder","group":"Attacking midfielders and forwards","duty":"attack","k":["dribbling","firstTouch","longShots","passing","technique","anticipation","decisions","flair","offTheBall"],"p":["finishing","composure","vision","agility"]},{"id":"bwm-defend","role":"bwm","name":"Ball-Winning Midfielder","group":"Central and defensive midfielders","duty":"defend","k":["tackling","aggression","anticipation","teamwork","workRate","stamina"],"p":["marking","bravery","concentration","positioning","agility","pace","strength"]},{"id":"bwm-support","role":"bwm","name":"Ball-Winning Midfielder","group":"Central and defensive midfielders","duty":"support","k":["tackling","aggression","anticipation","teamwork","workRate","stamina"],"p":["marking","passing","bravery","concentration","agility","pace","strength"]},{"id":"bbm-support","role":"bbm","name":"Box-to-Box Midfielder","group":"Central and defensive midfielders","duty":"support","k":["passing","tackling","offTheBall","teamwork","workRate","stamina"],"p":["dribbling","finishing","firstTouch","longShots","technique","aggression","anticipation","composure","decisions","positioning","acceleration","balance","pace","strength"]},{"id":"car-support","role":"car","name":"Carrilero","group":"Central and defensive midfielders","duty":"support","k":["firstTouch","passing","tackling","decisions","positioning","teamwork","stamina"],"p":["technique","anticipation","composure","concentration","offTheBall","vision","workRate"]},{"id":"cm-defend","role":"cm","name":"Central Midfielder","group":"Central and defensive midfielders","duty":"defend","k":["tackling","concentration","decisions","positioning","teamwork"],"p":["firstTouch","marking","passing","technique","aggression","anticipation","composure","workRate","stamina"]},{"id":"cm-support","role":"cm","name":"Central Midfielder","group":"Central and defensive midfielders","duty":"support","k":["firstTouch","passing","tackling","decisions","teamwork"],"p":["technique","anticipation","composure","concentration","offTheBall","vision","workRate","stamina"]},{"id":"cm-attack","role":"cm","name":"Central Midfielder","group":"Central and defensive midfielders","duty":"attack","k":["firstTouch","passing","decisions","offTheBall"],"p":["longShots","tackling","technique","anticipation","composure","teamwork","vision","workRate","acceleration","stamina"]},{"id":"dlp-defend","role":"dlp","name":"Deep-Lying Playmaker","group":"Central and defensive midfielders","duty":"defend","k":["firstTouch","passing","technique","composure","decisions","teamwork","vision"],"p":["tackling","anticipation","positioning","balance"]},{"id":"dlp-support","role":"dlp","name":"Deep-Lying Playmaker","group":"Central and defensive midfielders","duty":"support","k":["firstTouch","passing","technique","composure","decisions","teamwork","vision"],"p":["anticipation","offTheBall","positioning","balance"]},{"id":"dm-defend","role":"dm","name":"Defensive Midfielder","group":"Central and defensive midfielders","duty":"defend","k":["tackling","anticipation","concentration","positioning","teamwork"],"p":["marking","passing","aggression","composure","decisions","workRate","stamina","strength"]},{"id":"dm-support","role":"dm","name":"Defensive Midfielder","group":"Central and defensive midfielders","duty":"support","k":["tackling","anticipation","concentration","positioning","teamwork"],"p":["firstTouch","marking","passing","aggression","composure","decisions","workRate","stamina","strength"]},{"id":"dw-defend","role":"dw","name":"Defensive Winger","group":"Wide roles","duty":"defend","k":["technique","anticipation","offTheBall","positioning","teamwork","workRate","stamina"],"p":["crossing","dribbling","firstTouch","marking","tackling","aggression","concentration","decisions","acceleration"]},{"id":"dw-support","role":"dw","name":"Defensive Winger","group":"Wide roles","duty":"support","k":["crossing","technique","offTheBall","teamwork","workRate","stamina"],"p":["dribbling","firstTouch","marking","passing","tackling","aggression","anticipation","composure","concentration","decisions","positioning","acceleration"]},{"id":"eng-support","role":"eng","name":"Enganche","group":"Attacking midfielders and forwards","duty":"support","k":["firstTouch","passing","technique","composure","decisions","vision"],"p":["dribbling","anticipation","flair","offTheBall","agility"]},{"id":"hb-defend","role":"hb","name":"Half Back","group":"Central and defensive midfielders","duty":"defend","k":["marking","tackling","anticipation","composure","concentration","decisions","positioning","teamwork"],"p":["firstTouch","passing","aggression","bravery","workRate","jumpingReach","stamina","strength"]},{"id":"if-support","role":"if","name":"Inside Forward","group":"Wide roles","duty":"support","k":["dribbling","finishing","firstTouch","technique","offTheBall","acceleration","agility"],"p":["longShots","passing","anticipation","composure","flair","vision","workRate","balance","pace","stamina"]},{"id":"if-attack","role":"if","name":"Inside Forward","group":"Wide roles","duty":"attack","k":["dribbling","finishing","firstTouch","technique","anticipation","offTheBall","acceleration","agility"],"p":["longShots","passing","composure","flair","workRate","balance","pace","stamina"]},{"id":"iw-support","role":"iw","name":"Inverted Winger","group":"Wide roles","duty":"support","k":["crossing","dribbling","passing","technique","acceleration","agility"],"p":["firstTouch","longShots","composure","decisions","offTheBall","vision","workRate","balance","pace","stamina"]},{"id":"iw-attack","role":"iw","name":"Inverted Winger","group":"Wide roles","duty":"attack","k":["crossing","dribbling","passing","technique","acceleration","agility"],"p":["firstTouch","longShots","anticipation","composure","decisions","flair","offTheBall","vision","workRate","balance","pace","stamina"]},{"id":"mez-support","role":"mez","name":"Mezzala","group":"Central and defensive midfielders","duty":"support","k":["passing","technique","decisions","offTheBall","workRate","acceleration"],"p":["dribbling","firstTouch","longShots","tackling","anticipation","composure","vision","balance","stamina"]},{"id":"mez-attack","role":"mez","name":"Mezzala","group":"Central and defensive midfielders","duty":"attack","k":["dribbling","passing","technique","decisions","offTheBall","vision","workRate","acceleration"],"p":["finishing","firstTouch","longShots","anticipation","composure","flair","balance","stamina"]},{"id":"rmd-attack","role":"rmd","name":"Raumdeuter","group":"Wide roles","duty":"attack","k":["finishing","anticipation","composure","concentration","decisions","offTheBall","balance"],"p":["firstTouch","technique","workRate","acceleration","stamina"]},{"id":"reg-support","role":"reg","name":"Regista","group":"Central and defensive midfielders","duty":"support","k":["firstTouch","passing","technique","composure","decisions","flair","offTheBall","teamwork","vision"],"p":["dribbling","longShots","anticipation","balance"]},{"id":"rpm-support","role":"rpm","name":"Roaming Playmaker","group":"Central and defensive midfielders","duty":"support","k":["firstTouch","passing","technique","anticipation","composure","decisions","offTheBall","teamwork","vision","workRate","acceleration","stamina"],"p":["dribbling","longShots","concentration","positioning","agility","balance","pace"]},{"id":"sv-support","role":"sv","name":"Segundo Volante","group":"Central and defensive midfielders","duty":"support","k":["marking","passing","tackling","offTheBall","positioning","workRate","pace","stamina"],"p":["finishing","firstTouch","longShots","anticipation","composure","concentration","decisions","acceleration","balance","strength"]},{"id":"sv-attack","role":"sv","name":"Segundo Volante","group":"Central and defensive midfielders","duty":"attack","k":["finishing","longShots","passing","tackling","anticipation","offTheBall","positioning","workRate","pace","stamina"],"p":["firstTouch","marking","composure","concentration","decisions","acceleration","balance","strength"]},{"id":"ss-attack","role":"ss","name":"Shadow Striker","group":"Attacking midfielders and forwards","duty":"attack","k":["dribbling","finishing","firstTouch","anticipation","composure","offTheBall","acceleration"],"p":["passing","technique","concentration","decisions","workRate","agility","balance","pace","stamina"]},{"id":"wm-defend","role":"wm","name":"Wide Midfielder","group":"Wide roles","duty":"defend","k":["passing","tackling","concentration","decisions","positioning","teamwork","workRate"],"p":["crossing","firstTouch","marking","technique","anticipation","composure","stamina"]},{"id":"wm-support","role":"wm","name":"Wide Midfielder","group":"Wide roles","duty":"support","k":["passing","tackling","decisions","teamwork","workRate","stamina"],"p":["crossing","firstTouch","technique","anticipation","composure","concentration","offTheBall","positioning","vision"]},{"id":"wm-attack","role":"wm","name":"Wide Midfielder","group":"Wide roles","duty":"attack","k":["crossing","firstTouch","passing","decisions","teamwork","workRate","stamina"],"p":["tackling","technique","anticipation","composure","offTheBall","vision"]},{"id":"wp-support","role":"wp","name":"Wide Playmaker","group":"Wide roles","duty":"support","k":["firstTouch","passing","technique","composure","decisions","teamwork","vision"],"p":["dribbling","offTheBall","agility"]},{"id":"wp-attack","role":"wp","name":"Wide Playmaker","group":"Wide roles","duty":"attack","k":["dribbling","firstTouch","passing","technique","composure","decisions","offTheBall","teamwork","vision"],"p":["anticipation","flair","acceleration","agility"]},{"id":"wtf-support","role":"wtf","name":"Wide Target Forward","group":"Wide roles","duty":"support","k":["heading","bravery","teamwork","jumpingReach","strength"],"p":["crossing","firstTouch","anticipation","offTheBall","workRate","balance","stamina"]},{"id":"wtf-attack","role":"wtf","name":"Wide Target Forward","group":"Wide roles","duty":"attack","k":["heading","bravery","offTheBall","jumpingReach","strength"],"p":["crossing","finishing","firstTouch","anticipation","teamwork","workRate","balance","stamina"]},{"id":"w-support","role":"w","name":"Winger","group":"Wide roles","duty":"support","k":["crossing","dribbling","technique","acceleration","agility"],"p":["firstTouch","passing","offTheBall","workRate","balance","pace","stamina"]},{"id":"w-attack","role":"w","name":"Winger","group":"Wide roles","duty":"attack","k":["crossing","dribbling","technique","acceleration","agility"],"p":["firstTouch","passing","anticipation","flair","offTheBall","workRate","balance","pace","stamina"]},{"id":"af-attack","role":"af","name":"Advanced Forward","group":"Attacking midfielders and forwards","duty":"attack","k":["dribbling","finishing","firstTouch","technique","composure","offTheBall","acceleration"],"p":["passing","anticipation","decisions","workRate","agility","balance","pace","stamina"]},{"id":"cf-support","role":"cf","name":"Complete Forward","group":"Attacking midfielders and forwards","duty":"support","k":["dribbling","firstTouch","heading","longShots","passing","technique","anticipation","composure","decisions","offTheBall","vision","acceleration","agility","strength"],"p":["finishing","teamwork","workRate","balance","jumpingReach","pace","stamina"]},{"id":"cf-attack","role":"cf","name":"Complete Forward","group":"Attacking midfielders and forwards","duty":"attack","k":["dribbling","finishing","firstTouch","heading","technique","anticipation","composure","offTheBall","acceleration","agility","strength"],"p":["longShots","passing","decisions","teamwork","vision","workRate","balance","jumpingReach","pace","stamina"]},{"id":"dlf-support","role":"dlf","name":"Deep-Lying Forward","group":"Attacking midfielders and forwards","duty":"support","k":["firstTouch","passing","technique","composure","decisions","offTheBall","teamwork"],"p":["finishing","anticipation","flair","vision","balance","strength"]},{"id":"dlf-attack","role":"dlf","name":"Deep-Lying Forward","group":"Attacking midfielders and forwards","duty":"attack","k":["firstTouch","passing","technique","composure","decisions","offTheBall","teamwork"],"p":["dribbling","finishing","anticipation","flair","vision","balance","strength"]},{"id":"f9-support","role":"f9","name":"False Nine","group":"Attacking midfielders and forwards","duty":"support","k":["dribbling","firstTouch","passing","technique","composure","decisions","offTheBall","vision","acceleration","agility"],"p":["finishing","anticipation","flair","teamwork","balance"]},{"id":"p-attack","role":"p","name":"Poacher","group":"Attacking midfielders and forwards","duty":"attack","k":["finishing","anticipation","composure","offTheBall"],"p":["firstTouch","heading","technique","decisions","acceleration"]},{"id":"pf-defend","role":"pf","name":"Pressing Forward","group":"Attacking midfielders and forwards","duty":"defend","k":["aggression","anticipation","bravery","decisions","teamwork","workRate","acceleration","pace","stamina"],"p":["firstTouch","composure","concentration","agility","balance","strength"]},{"id":"pf-support","role":"pf","name":"Pressing Forward","group":"Attacking midfielders and forwards","duty":"support","k":["aggression","anticipation","bravery","decisions","teamwork","workRate","acceleration","pace","stamina"],"p":["firstTouch","passing","composure","concentration","offTheBall","agility","balance","strength"]},{"id":"pf-attack","role":"pf","name":"Pressing Forward","group":"Attacking midfielders and forwards","duty":"attack","k":["aggression","anticipation","bravery","offTheBall","teamwork","workRate","acceleration","pace","stamina"],"p":["finishing","firstTouch","composure","concentration","decisions","agility","balance","strength"]},{"id":"tf-support","role":"tf","name":"Target Forward","group":"Attacking midfielders and forwards","duty":"support","k":["heading","bravery","teamwork","balance","jumpingReach","strength"],"p":["finishing","firstTouch","aggression","anticipation","composure","decisions","offTheBall"]},{"id":"tf-attack","role":"tf","name":"Target Forward","group":"Attacking midfielders and forwards","duty":"attack","k":["finishing","heading","bravery","composure","offTheBall","balance","jumpingReach","strength"],"p":["firstTouch","aggression","anticipation","decisions","teamwork"]},{"id":"t-attack","role":"t","name":"Trequartista","group":"Attacking midfielders and forwards","duty":"attack","k":["dribbling","firstTouch","passing","technique","composure","decisions","flair","offTheBall","vision","acceleration"],"p":["finishing","anticipation","agility","balance"]}];
for (const r of ROLES) r.denom = r.k.length * 2 + r.p.length;

/* ---------- cálculo de role rating (fórmula "Role Highlighted Rating") ---------- */
function rateRole(role, attributes) {
  let total = 0;
  for (const k of role.k) {
    const v = attributes[k];
    if (typeof v !== 'number' || v < 1 || v > 20) return null;
    total += v * 2;
  }
  for (const k of role.p) {
    const v = attributes[k];
    if (typeof v !== 'number' || v < 1 || v > 20) return null;
    total += v * 1;
  }
  return (5 * total) / role.denom;
}
function ratePlayerRoles(attributes) {
  return ROLES.map((role) => ({ role, score: rateRole(role, attributes) }))
    .filter((r) => r.score !== null)
    .sort((a, b) => b.score - a.score);
}
function bestRole(attributes) {
  const rated = ratePlayerRoles(attributes);
  return rated.length ? rated[0] : null;
}

/* ---------- formações e sugestão de XI ideal (heurística gananciosa) ---------- */
const FORMATIONS = {
  f442: { label: '4-4-2 Clássico', slots: [
    { label: 'GR', pos: ['GK'], role: 'gk-defend' },
    { label: 'DD', pos: ['DR'], role: 'fb-support' },
    { label: 'DC', pos: ['DC'], role: 'cd-defend' },
    { label: 'DC', pos: ['DC'], role: 'cd-defend' },
    { label: 'DE', pos: ['DL'], role: 'fb-support' },
    { label: 'MD', pos: ['MR'], role: 'wm-support' },
    { label: 'MC', pos: ['MC'], role: 'cm-support' },
    { label: 'MC', pos: ['MC'], role: 'bwm-support' },
    { label: 'ME', pos: ['ML'], role: 'wm-support' },
    { label: 'PL', pos: ['ST'], role: 'af-attack' },
    { label: 'PL', pos: ['ST'], role: 'dlf-support' },
  ]},
  f433: { label: '4-3-3 Ofensivo', slots: [
    { label: 'GR', pos: ['GK'], role: 'gk-defend' },
    { label: 'DD', pos: ['DR'], role: 'fb-support' },
    { label: 'DC', pos: ['DC'], role: 'cd-defend' },
    { label: 'DC', pos: ['DC'], role: 'cd-defend' },
    { label: 'DE', pos: ['DL'], role: 'fb-support' },
    { label: 'MDC', pos: ['DM'], role: 'dm-support' },
    { label: 'MC', pos: ['MC'], role: 'cm-support' },
    { label: 'MC', pos: ['MC'], role: 'bbm-support' },
    { label: 'ED', pos: ['AMR'], role: 'if-support' },
    { label: 'PL', pos: ['ST'], role: 'af-attack' },
    { label: 'EE', pos: ['AML'], role: 'if-support' },
  ]},
  f4231: { label: '4-2-3-1', slots: [
    { label: 'GR', pos: ['GK'], role: 'gk-defend' },
    { label: 'DD', pos: ['DR'], role: 'fb-support' },
    { label: 'DC', pos: ['DC'], role: 'cd-defend' },
    { label: 'DC', pos: ['DC'], role: 'cd-defend' },
    { label: 'DE', pos: ['DL'], role: 'fb-support' },
    { label: 'MDC', pos: ['DM'], role: 'dm-defend' },
    { label: 'MDC', pos: ['DM'], role: 'dlp-support' },
    { label: 'ED', pos: ['AMR'], role: 'w-support' },
    { label: 'MAC', pos: ['AMC'], role: 'ap-support' },
    { label: 'EE', pos: ['AML'], role: 'w-support' },
    { label: 'PL', pos: ['ST'], role: 'af-attack' },
  ]},
  f352: { label: '3-5-2', slots: [
    { label: 'GR', pos: ['GK'], role: 'gk-defend' },
    { label: 'DC', pos: ['DC'], role: 'cd-defend' },
    { label: 'DC', pos: ['DC'], role: 'cd-cover' },
    { label: 'DC', pos: ['DC'], role: 'cd-defend' },
    { label: 'ALD', pos: ['WBR', 'DR'], role: 'wb-support' },
    { label: 'MC', pos: ['MC'], role: 'cm-support' },
    { label: 'MC', pos: ['MC'], role: 'bbm-support' },
    { label: 'MDC', pos: ['DM'], role: 'dm-support' },
    { label: 'ALE', pos: ['WBL', 'DL'], role: 'wb-support' },
    { label: 'PL', pos: ['ST'], role: 'af-attack' },
    { label: 'PL', pos: ['ST'], role: 'cf-support' },
  ]},
};
const ROLE_BY_ID = new Map(ROLES.map((r) => [r.id, r]));

function suggestBestXI(players, formationKey) {
  const formation = FORMATIONS[formationKey];
  const slots = formation.slots;
  const pairs = [];
  slots.forEach((slot, si) => {
    const role = ROLE_BY_ID.get(slot.role);
    players.forEach((p) => {
      if (!slot.pos.some((pos) => p.positions.includes(pos))) return;
      const score = rateRole(role, p.attributes);
      if (score !== null) pairs.push({ si, playerId: p.id, score });
    });
  });
  pairs.sort((a, b) => b.score - a.score);
  const slotAssigned = new Array(slots.length).fill(null);
  const usedPlayers = new Set();
  for (const pair of pairs) {
    if (slotAssigned[pair.si] || usedPlayers.has(pair.playerId)) continue;
    slotAssigned[pair.si] = pair;
    usedPlayers.add(pair.playerId);
  }
  const byId = new Map(players.map((p) => [p.id, p]));
  const result = slots.map((slot, si) => {
    const a = slotAssigned[si];
    return {
      label: slot.label,
      roleName: ROLE_BY_ID.get(slot.role).name,
      duty: ROLE_BY_ID.get(slot.role).duty,
      player: a ? byId.get(a.playerId) : null,
      score: a ? a.score : null,
    };
  });
  const total = result.reduce((s, r) => s + (r.score ?? 0), 0);
  const filled = result.filter((r) => r.player).length;
  return { formationLabel: formation.label, slots: result, total, filled, count: slots.length };
}


export { parseSave, ROLES, ATTRIBUTES, POSITIONS, rateRole, NATIONS };
