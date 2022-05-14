%
% LM-OTS One-Time Signature main program (Leighton-Micali OTS)
%
% ref. Leighton-Micali Hash-Based Signatures, Apr 2019, p.12
%
clear;
clc;
% LMOTS_time = cputime;
starting_time = cputime; % fetch the current cputime as the starting time
%
% 4.1 Parameters
%
% n:  the number of bytes of the output of the hash function that we chosed.
%     in this case, SHA256. n has strong effect on security
%
% w:  the number of bits {1, 2, 4, 8}. w describes a space/time trade-off; 
%     the choice of bigger w will shorten the signature while increasing
%     the time and computation needed for its generation and verification,
%     has little effect on security
% 
% p:  p = u + v, the numer of n-byte string elements(independent W. chain) used in the signature
%     u = ceil(8*n/w), the number that w-bit field required to hold the n-bit hash 
%     v = ceil(floor(log((2^w-1)*u))+1/w), the number that wbf required to hold the checksum
%
% ls: ls = 16 - (v*w), the number of left-shift bits needed and used in checksum
%
% 4.2. Private Key. Generating a Private Key
%
fprintf('Algorithm 0: Generating a Private Key. \n');
%
% 1. Retrive the value of q and I
q = '00000005'; % indicate a certain leaf, e.g. fifth leaf
I = '61a5d57d37f5e46bfb7520806b07a1b8';
%
% 2. Set the type to the typecode of the algorithm
otstype = 'LMOTS_SHA256_N32_W1'; % 1 of 4 OTS_types
%
% 3. Set n, w, p, and ls according to the typecode and Table 1
if strcmp(otstype, 'LMOTS_SHA256_N32_W1') == 1
    % if its W1 type
    n = 32;
    w = 1;
    p = 265;
    ls = 7;
    % sig_len = 8516;
elseif strcmp(otstype, 'LMOTS_SHA256_N32_W2') == 1
    % if its W2 type
    n = 32;
    w = 2;
    p = 133;
    ls = 6;
    % sig_len = 4292;
elseif strcmp(otstype, 'LMOTS_SHA256_N32_W4') == 1
    % if its W4 type
    n = 32;
    w = 4;
    p = 67;
    ls = 4;
    % sig_len = 2180;
elseif strcmp(otstype, 'LMOTS_SHA256_N32_W8') == 1
    % if its W8 type
    n = 32;
    w = 8;
    p = 34;
    ls = 0;
    % sig_len = 1124;
end
%
% 4. Compute the array x of size p, set x[i] to a uniformly random n-byte string
% random char string x, for Public and Private Key generation
x = char();
for ip = 1 : p
    % set x[i] to a uniformly random n-byte string
    for in = 1 : n
        xx = rand(1, 8);
        xx = xx > 0.5; % if greater than 0.5, xx = 1
        xx = char(xx + 48); % ASCII code 48 == 0
        x(ip, (in-1)*2 + 1 : in*2) = lower(dec2hex(bin2dec(xx), 2));
        % x(ip, (in-1)*2 + 1 : in*2) = lower(bin2hex(xx, 2));
    end
end
%
% 5. Return u32str(type) || I || u32str(q) || x[0] || x[1] || ... || x[p-1]
LMOTS_private_key = strcat(otstype, I, q);
for ip = 1 : p
    LMOTS_private_key = strcat(LMOTS_private_key, x(ip, :));
end
%
% 4.3 Public Key, Generating a One-Time Signature Public Key From a Private Key
%
fprintf('Algorithm 1: Generating a One-Time Signature Public Key. \n');
%
% 1. Set the type to the typecode of the algorithm, done above
%
% 2. Set n, w, p, and ls according to the typecode and Table 1, done above
%
% 3. Determine x, I, and q from the Private Key, calculated above already
%
% 4. Compute the string K
y = char();
for ip = 1 : p
    % temp = x[i]
    temp = x(ip, :);
    for j = 1 : 2^w
        % temp = H(I || u32str(q) || u16str(i) || u8str(j) || temp)
        II = strcat(I, q, lower(dec2hex(ip-1, 4)), lower(dec2hex(j-1, 2)), temp);
        temp = SHA256(II);
    end
    % y[i] = temp
    y(ip, :) = temp;
end
% K = H(I || u32str(q) || u16str(D_PBLC) || y[0] || ... || y[p-1]), 
%   D_PBLC is the fixed 2-byte value 0x8080 which is used to distinguish 
%   the last hash from every other hash.
II = strcat(I, q, '8080');
for ip = 1 : p
    II = strcat(II, y(ip, :));
end
K = SHA256(II);
%
% 5. Return u32str(type) || I || u32str(q) || K
LMOTS_public_key = strcat(otstype, I, q, K);
%
% 4.4 Checksum
%
fprintf('Algorithm 2: Checksum Calculation \n');
%
% calculation done by subfunction cksm.m
% 
% sum = 0;
% for i = 1 : n*8/w
%     sum = sum + (2^w - 1) - coef(S, i-1, w);
% end
% return (sum << ls)

%
% 4.5 Signatue Generation, Generating a One-Time Signature From a Private Key and a Message.
%
fprintf('Algorithm 3: Generating a One-Time Signature. \n');
%
% 1. Set the type to the typecode of the algorithm, done above
%
% 2. Set n, w, and p according to the typecode and Table 1, done above
%
% 3. Determine x, I, and q from the Private Key, calculated above already
%
% 4. Set C to a uniformly random n-byte string
C = char(); % generating random char string
for in = 1 : n
    cc = rand(1, 8);
    cc = cc > 0.5; % if greater than 0.5, cc = 1
    cc = char(cc + 48); % ASCII code 48 == 0
    C(1, (in-1)*2 + 1 : in*2) = lower(dec2hex(bin2dec(cc), 2));
    % C(1, (in-1)*2 + 1 : in*2) = lower(bin2hex(cc, 2));
end
%
% 5. Compute the array y 
message = '54686520706f77657273206e6f742064656c65676174656420746f2074686520556e69746564205374617465732062792074686520436f6e737469747574696f6e2c206e6f722070726f6869626974656420627920697420746f20746865205374617465732c2061726520726573657276656420746f207468652053746174657320726573706563746976656c792c206f7220746f207468652070656f706c652e0a';
II = strcat(I, q, '8181', C, message);
Q = SHA256(II);
QQ = strcat(Q, cksm(Q, n, w, ls));
y = char();
% y_sig = char();
for ip = 1 : p
    % QQ = strcat(Q, cksm(Q, n, w, ls));
    a = coef(QQ, ip-1, w);
    temp = x(ip, :);
    for j = 1 : a
        % temp = H(I || u32str(q) || u16str(i) || u8str(j) || temp)
        II = strcat(I, q, lower(dec2hex(ip-1, 4)), lower(dec2hex(j-1, 2)), temp);
        temp = SHA256(II);
    end
    % y[i] = temp
    y(ip, :) = temp;
    % y_sig(ip, :) = temp;
end
%
% 6. Return u32str(type) || C || y[0] || ... || y[p-1]
LMOTS_signature = strcat(otstype, C);
for ip = 1 : p
    % LMOTS_signature = strcat(LMOTS_signature, y(ip, :));
    LMOTS_signature = strcat(LMOTS_signature, y(ip, :));
end
%
% 4.6 Signature Verification
%
fprintf('Algorithm 4a: Verifying Signature and Message Using Public Key. \n');
%
% 1. If the Public Key is not at least 4-bytes long, return INVALID.
%
% 2. Parse pubyte, I, q, and K from the public key as follows:
%    a. pubyte = strTou32(first 4-bytes of the public key)
%    b. Set n according to pubkey and Table 1; if public key is not exactly
%       (24 + n) bytes long, return INVALID
%    c. I = next 16-bytes of the public key
%    d. q = strTou32(next 4-bytes of the public key)
%    e. K = next n-bytes of the public key
%
% 3. Using Algorithm 4b to compute the key candidate Kc from signature, message, 
%    pubyte, and identifier I and q
%
% 4. (Kc == K) ? return VALID : return INVALID
%
fprintf('Algorithm 4b: Computing Public Key Candidate Kc. \n');
%
% 1. If the Signature is not at least 4-bytes long, return INVALID.
%
% 2. Parse sigtype, C, and y from the signature as follows:
%    a. sigtype = strTou32(first 4-bytes of the signature)
%    b. If sigtype != pubyte, return INVALID
%    c. Set n according to pubkey and Table 1; if public key is not exactly
%       (24 + n) bytes long, return INVALID
%    d. C = next n-bytes of the signature
%    e. y[0]  = next n-bytes of the signature
%       y[1]  = next n-bytes of the signature
%       ...
%       y[p-1] = next n-bytes of the signature
%
% 3. Compute the string Kc
%
% 4. Return Kc
%
II = strcat(I, q, '8181', C, message);
Q = SHA256(II);
QQ = strcat(Q, cksm(Q, n, w, ls));
z = char();
for ip = 1 : p
    % QQ = strcat(Q, cksm(Q, n, w, ls));
    a = coef(QQ, ip-1, w);
    temp = y(ip, :);
    for j = a + 1 : 2^w
        % temp = H(I || u32str(q) || u16str(i) || u8str(j) || temp)
        II = strcat(I, q, lower(dec2hex(ip-1, 4)), lower(dec2hex(j-1, 2)), temp);
        temp = SHA256(II);
    end
    % z[i] = temp
    z(ip, :) = temp;
end
%
II = strcat(I, q, '8080');
for ip = 1 : p
    II = strcat(II, z(ip, :));
end
Kc = SHA256(II);
%
if strcmp(K, Kc) == 1
    fprintf('VALID \n');
else
    fprintf('INVALID \n');
end
%
ending_time = cputime; % fetch the current cputime as the ending time
LMOTS_time = ending_time - starting_time; % ending time - starting time
% LMOTS_time = cputime - LMOTS_time;
%
fprintf('the computation time is: %f\n', LMOTS_time);
%
