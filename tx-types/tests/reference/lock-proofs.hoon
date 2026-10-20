::  Reference inputs match hoon/tests/dumb/mod/unit/lock-merkle-proof.hoon.
/=  t  /common/tx-engine-1
/=  zo  /common/zoon
/=  z  /common/zeke
=<  $
|%
++  $
  %+  turn  ~[1 2 4 8 16]
  |=  arity=@
  =/  pkh-one  (pkh default-a-pt-1)
  =/  pkh-two  (pkh default-a-pt-2)
  =/  pkh-three  (pkh default-a-pt-3)
  =/  scs=(list spend-condition:t)
    ?:  =(arity 1)  ~[pkh-one]
    ?:  =(arity 2)  ~[pkh-one pkh-two]
    %+  weld  ~[pkh-one pkh-two pkh-three]
    %+  turn  (gulf 4 arity)
    |=  index=@
    =/  value=@
      ?:  =(arity 4)  42
      (add ?:(=(arity 8) 100 200) (sub index 4))
    (hax value)
  =/  lk=lock:t  (from-list:lock:t scs)
  =/  root=hash:t  (hash:lock:t lk)
  =/  first=hash:t  (hash-hashable:tip5:z [leaf+& hash+root])
  :-  lk
  :-  root
  %+  turn  (gulf 1 arity)
  |=  index=@
  =/  stub  (build-lock-merkle-proof-stub:lock:t lk index)
  =/  full  (build-lock-merkle-proof-full:lock:t lk index)
  :*  index
      stub
      full
      (hash:lock-merkle-proof:t stub)
      (hash:lock-merkle-proof:t full)
      (check:lock-merkle-proof:t stub first)
      (check:lock-merkle-proof:t full first)
  ==
::
++  pkh
  |=  key=schnorr-pubkey:t
  ^-  spend-condition:t
  =/  digest=hash:t  (hash:schnorr-pubkey:t key)
  ~[[%pkh 1 (~(put z-in:zo *(z-set:zo hash:t)) digest)]]
::
++  hax
  |=  pre=@
  ^-  spend-condition:t
  =/  digest=hash:t  (hash-noun:hax:t pre)
  ~[[%hax (~(put z-in:zo *(z-set:zo hash:t)) digest)]]
::
++  default-a-pt-1
  ^-  schnorr-pubkey:t
  :*  :*  a0=18.211.575.932.483.365.338
          a1=18.084.541.669.437.144.090
          a2=13.716.509.772.206.322.211
          a3=13.903.522.087.582.572.864
          a4=8.355.231.558.426.062.419
          a5=1.785.159.202.319.376.064
      ==
      :*  a0=6.862.026.292.343.821.647
          a1=3.472.296.653.227.435.007
          a2=14.264.708.252.454.369.462
          a3=12.448.508.371.644.144.441
          a4=10.672.764.440.307.750.310
          a5=7.731.969.120.172.842.597
      ==
      %.n
  ==
::
++  default-a-pt-2
  ^-  schnorr-pubkey:t
  :*  :*  a0=8.112.277.360.505.529.168
          a1=13.815.204.321.620.730.735
          a2=4.609.498.217.171.624.338
          a3=17.544.458.397.231.430.472
          a4=1.434.491.911.615.350.717
          a5=13.302.043.377.247.567.356
      ==
      :*  a0=2.952.868.476.347.789.052
          a1=2.195.947.167.671.474.841
          a2=5.041.105.011.183.230.411
          a3=201.486.871.654.097.277
          a4=384.883.694.750.811.959
          a5=2.832.411.450.844.530.203
      ==
      %.n
  ==
::
::
++  default-a-pt-3
  ^-  schnorr-pubkey:t
  :*  :*  a0=9.328.090.969.704.952.711
          a1=6.464.356.965.168.029.919
          a2=15.057.652.275.350.316.414
          a3=16.160.083.394.729.116.439
          a4=16.516.510.259.443.376.809
          a5=15.842.189.185.823.855.279
      ==
      :*  a0=8.160.803.705.266.360.847
          a1=4.180.418.860.702.279.974
          a2=8.077.237.076.284.994.865
          a3=10.695.087.701.690.147.905
          a4=9.145.798.145.442.941.712
          a5=8.788.211.494.469.384.813
      ==
      %.n
  ==
::
--
