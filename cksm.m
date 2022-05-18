%
% Checksum function
%
function out = cksm(S, n, w, ls)
sum = 0;
nw = n*8/w;
w2 = 2^w - 1;
for i = 1 : nw
    sum = sum + w2 - coef(S, i-1, w);
end
sum = bitshift(sum, ls); % shift left ls bits
out = dec2hex(sum, 4);

return
