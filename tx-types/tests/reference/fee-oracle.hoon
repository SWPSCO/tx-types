::  Fee/count gates from common/tx-engine.hoon at the documented reference pin.
/=  t  /common/tx-engine-1
/=  zo  /common/zoon
/=  z  /common/zeke
=<  oracle
|%
++  oracle
  =/  raw=raw-tx:t
    ;;(raw-tx:t (cue 0x1.0452.1c00.7041.1487.2b89.e9f8.73f7.0338.0403.08ba.6849.408c.4b6e.01d6.4e8d.2246.3198.3002.00e9.bdf7.0552.b2ec.6e81.0060.d1eb.928f.5b06.fb00.803e.7480.e034.1148.7643.831b.2b97.c056.dcc2.d0c7.f015.82a6.5bb9.cd93.b92c.0201.1cd9.cf4f.75a4.b6e7.a01d.5124.4e3a.a4e3.4b5f.8063.1afa.40b6.94a4.6080.8038.9f32.4905.2551.12e0.4016.5682.290e.fbbc.2055.41dc.cae0.dff0.1d6c.6ded.8dce.af80.62aa.4356.8229.0f76.879c.1b03.f9bf.aba8.100f.c298.bc98.2018.267e.3770.1e03.0d79.3a03.f964.4c47.406e.2c2d.03fc.0731.1a87.c010.0f4e.ff28.b606.917b.255f.80c1.5ccb.adf8.0f25.0cca.7820.1c25.4b70.b040.3ba5.6310.8080.75bc.e40f.203e.07da.24e0.805c.9d3a.fcd4.c559.186f.d015.5d86.b985.d91c.df70.0d97.a67c.07b1.c2fb.a806.2fac.d263.d824.ee5f.e01f.3cc9.283d.4aad.4cf6.01a3.eac8.efe4.a2bb.f3d0.0b71.34b3.f2df.5b7b.f804.027d.0ad9.6320.20f7.bd80.7cde.9bfd.4be6.4ed2.0080.3ffc.1d1a.69a7.d0c9.7a01.bfb9.7722.69a5.236f.0200.f094.9947.5860.2350.fc02.ba5d.c356.e6cd.4467.c08d.1e85.7804.03d2.f4e0.d208.0692.0d07.6010.0c6a.42c8.fd01.b8ec.e9bd.0403.972b.cab4.0807.ec1b.202e.80c5.2549.65d0.2b44.82b8.0100.ce7e.323b.8201.d53a.f833.0403.1035.50bd.80df.e379.6082.018b.68f7.bfa0.3308.278b.0080.5cd6.9af1.e5ec.623c.cbf8.0941.d46b.633f.6d5a.6020.0d66.0fe3.459a.9ad9.c810.0717.d9b2.4fd0.80e2.d808.0381.809b.45d3.311f.ffa0.1be7.5a11.cd51.6aa9.ff80.5c63.146b.0ce2.0f60.7603.9f9d.f6ad.00f3.729f.e01c.0f33.bacb.5282.1400.200d.f2d6.a7b7.9441.9118.1007.ebe4.cb54.5233.f068.0803.f979.07a4.9f72.d3b4.0401.5a1a.e1ab.4dcc.1f96.e081.19de.0100.d666.376d.3946.a6e7.f806.926d.8bf9.17dc.fb37.e018.c88e.4d57.79e6.8c7f.807f.40df.adc7.b997.f1c0.802e.d00d.80a9.b1f1.58b8.100d.08fd.e669.8cba.a550.200d.1aca.e694.b738.751f.c03c.87d3.5db6.a513.3a3f.00c3.9f07.99dc.d931.e981.005d.65d6.4514.9912.9780.e4ac.342e.1ae5.133f.d00c.7cbb.b9b5.06ba.988f.c03d.4eb3.3896.2de4.e0ff.00d8.105f.5032.fbd5.a401.005d.8682.290f.c3a9.963a.9740.53d7.e033.0ef7.0b57.71a3.a7fe.0193.fb5d.0189.6859.3c02.00f8.fe08.c7ac.e222.a3b0.0f47.8d2e.84fa.8be0.e810.05f0.c2d0.f016.a309.6884.e895.dad2.e8f0.16a7.24bf.85a4.a753.d40f.406a.2bec.5f52.0939.d301.0075.726d.0d70.d88a.c6f4.03d5.d84b.2963.ce83.7404.01b0.3168.66f1.4a87.8902.00ae.2077.cd72.6024.56e0.100d.bb49.56b2.24b1.ee10.200f.3169.a6ac.28f8.7c10.1006.8072.2d90.32c0.6c39.00f8.9a7d.af6e.e812.adc0.2c87.435b.83c0.5763.63ab.37c0.571b.6fd8.a6b7.3d8b.e00f.e03f.8bce.7d73.d275.b4fe.01fb.200d.6bb8.a2af.d602.00e8.4ed8.3b7e.d9c0.8ffc.0346.6445.ed37.01e7.4fa0.16ce.6e71.02e3.30ae.ec08.0699.c460.a31a.6a7a.bfc0.3217.3422.dd73.c6ed.7a01.8b58.52a3.67d4.eded.f807.6f18.dfbe.7edf.f6ff.402a.ece3.b877.ce82.0dd2.fc05.e1e9.25ea.e999.dd3f.c030.3836.c5ec.92cf.3d60.401a.95df.3250.8ec0.785f.806b.609b.840f.a2e4.bbfe.0171))
  =/  row=[nam=nname:t sp=spend:t]  (snag 0 ~(tap z-by:zo spends.raw))
  =/  duplicate=spends:t
    (~(put z-by:zo spends.raw) ;;(nname:t [[1 2 3 4 5] [6 7 8 9 10] ~]) sp.row)
  =/  migration=spends:t
    (~(put z-by:zo *spends:t) nam.row [%0 [~ seeds.+.sp.row fee.+.sp.row]])
  =/  mixed=spends:t
    %+  ~(put z-by:zo duplicate)
      ;;(nname:t [[11 12 13 14 15] [16 17 18 19 20] ~])
    [%0 [~ seeds.+.sp.row fee.+.sp.row]]
  =/  cases=(list [@tas spends:t])
    ~[[%raw spends.raw] [%duplicate duplicate] [%migration migration] [%mixed mixed]]
  %-  zing
  %+  turn  cases
  |=  [case=@tas sps=spends:t]
  =/  heights=(list @)  ~[9 10 11]
  %+  turn  heights
  |=  height=@
  =/  seed-words=@
    ?:  (gte height 10)
      (count-seed-words-merged sps)
    (count-seed-words-legacy sps)
  =/  witness-words=@
    %+  roll  ~(tap z-by:zo sps)
    |=  [[nam=nname:t sp=spend:t] acc=@]
    %+  add  acc
    %-  num-of-leaves:shape:z
    ?-  -.sp
      %0  `*`signature.+.sp
      %1  `*`witness.+.sp
    ==
  =/  base=@  257
  =/  divisor=@  3
  =/  minimum=@  100
  =/  effective=@  ?:((gte height 10) base (mul 2 base))
  =/  discount=@  ?:((gte height 10) divisor 1)
  =/  fee=@
    %+  max  minimum
    (add (mul seed-words effective) (div (mul witness-words effective) discount))
  [case sps height base divisor minimum seed-words witness-words fee]
++  note-data-by-lock-root
  |=  sps=spends:t
  ^-  (z-mip:zo hash:t @tas *)
  =/  all-seeds=(list seed:t)
    %-  zing
    %+  turn  ~(tap z-by:zo sps)
    |=  [nam=nname:t sp=spend:t]
    ?-  -.sp
      %0  ~(tap z-in:zo seeds.+.sp)
      %1  ~(tap z-in:zo seeds.+.sp)
    ==
  =/  by-lock-root=(z-mip:zo hash:t @tas *)
    %+  roll  all-seeds
    |=  [sed=seed:t acc=(z-mip:zo hash:t @tas *)]
    =/  key=hash:t  lock-root.sed
    =/  existing=(unit (z-map:zo @tas *))
      (~(get z-by:zo acc) key)
    ?~  existing
      (~(put z-by:zo acc) key note-data.sed)
    =/  merged=(z-map:zo @tas *)
      (~(uni z-by:zo u.existing) note-data.sed)
    (~(put z-by:zo acc) key merged)
  by-lock-root
::  pre-bythos fee accounting charged note-data per spend, without lock-root
::  aggregation across the transaction.
++  count-seed-words-legacy
  |=  sps=spends:t
  ^-  @
  %+  roll  ~(tap z-by:zo sps)
  |=  [[nam=nname:t sp=spend:t] acc=@]
  =/  seds=seeds:t
    ?-  -.sp
      %0  seeds.+.sp
      %1  seeds.+.sp
    ==
  %+  add  acc
  %+  roll  ~(tap z-in:zo seds)
  |=  [sed=seed:t acc=@]
  %+  add  acc
  %-  num-of-leaves:shape:z
  %-  ~(rep z-by:zo note-data.sed)
  |=  [[k=@tas v=*] tree=*]
  [k v tree]
++  count-seed-words-merged
  |=  sps=spends:t
  ^-  @
  =/  merged-by-lock-root=(z-mip:zo hash:t @tas *)
    (note-data-by-lock-root sps)
  %+  roll  ~(tap z-by:zo merged-by-lock-root)
  |=  [[key=hash:t note-data=(z-map:zo @tas *)] acc=@]
  %+  add  acc
  %-  num-of-leaves:shape:z
  %-  ~(rep z-by:zo note-data)
  |=  [[k=@tas v=*] tree=*]
  [k v tree]
--
