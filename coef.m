%
% coef function
%
function out = coef(S, i, w)
  w2  = 2^w - 1;
  iw8 = floor(i * w/8);
  SS = hex2dec(S((iw8*2 + 1) : (iw8*2 + 2))); % from iw8*2 + 1 to iw8*2 + 2
  shift = 8 - (w * mod(i, 8/w) + w);
  SS  = bitshift(SS, -shift); % shift right shift bits
  out = bitand(w2, SS);
return



