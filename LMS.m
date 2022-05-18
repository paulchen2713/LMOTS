%
% LM Signature main program (Leighton-Micali)
%
% ref. Leighton-Micali Hash-Based Signatures, Apr 2019, p.19
%
% clear all;
clc;
%
% LM_time = cputime;
starting_time = cputime; % fetch the current cputime as the starting time
type = 'LMS_SHA_256_M32_H5';
q = '00000005';
I = '61a5d57d37f5e46bfb7520806b07a1b8';
otstype = 'LMOTS_SHA256_N32_W1'; % 1 of 4 OTS_types
message = '54686520706f77657273206e6f742064656c65676174656420746f2074686520556e69746564205374617465732062792074686520436f6e737469747574696f6e2c206e6f722070726f6869626974656420627920697420746f20746865205374617465732c2061726520726573657276656420746f207468652053746174657320726573706563746976656c792c206f7220746f207468652070656f706c652e0a';
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
% 5.1 Parameters
% 
% h: 
%
% m:
% 
% H:
% 
% 5.2. LMS Private Key, computing a LMS Private Key
%
fprintf('Algorithm 5: computing a LMS Private Key \n');
%
% 0. 
%
% 1. Determine h and m from the typecode and Table 2
if strcmp(type, 'LMS_SHA_256_M32_H5') == 1
    % if its H5 type
    m = 32;
    h = 5;
elseif strcmp(type, 'LMS_SHA_256_M32_H10') == 1
    % if its H10 type
    m = 32;
    h = 10;
elseif strcmp(type, 'LMS_SHA_256_M32_H15') == 1
    % if its H15 type
    m = 32;
    h = 15;
elseif strcmp(type, 'LMS_SHA_256_M32_H20') == 1
    % if its H20 type
    m = 32;
    h = 20;
elseif strcmp(type, 'LMS_SHA_256_M32_H25') == 1
    % if its H25 type
    m = 32;
    h = 25;
end
%
% 2. Set I to a uniformly random 16-byte string
I = char();
for ip = 1 : 16
    % set x[i] to a uniformly random n-byte string
    for in = 1 : n
        xx = rand(1, 8);
        xx = xx > 0.5; % if greater than 0.5, xx = 1
        xx = char(xx + 48); % ASCII code 48 == 0
        I(ip, (in-1)*2 + 1 : in*2) = lower(dec2hex(bin2dec(xx), 2));
        % x(ip, (in-1)*2 + 1 : in*2) = lower(bin2hex(xx, 2));
    end
end
%
% 3. Compute the array OTS_PRIV[]
OTS_PRIV = char();
X = char();
OTS_PUB_HASH = char(); 
for iq = 0 : 2^h-1
    % apply Appendix A. on p.45
    SEED = char();
    % set SEED[i] to a uniformly random n-byte string
    for in = 1 : n
        xx = rand(1, 8);
        xx = xx > 0.5; % if greater than 0.5, xx = 1
        xx = char(xx + 48);
        SEED(ip, (in-1)*2 + 1 : in*2) = lower(dec2hex(bin2dec(xx), 2));
        % SEED(ip, (in-1)*2 + 1 : in*2) = lower(bin2hex(xx, 2));
    end
    qq = lower(dec2hex(iq, 8));
    x = char();
    for ip = 0 : p-1
        II = strcat(I, qq, lower(dec2hex(ip, 4)), 'ff', SEED);
        x(ip + 1, :) = SHA256(II);
    end
    %
    OTS_private_key = strcat(otstype, I, qq);
    for ip = 1 : p
        OTS_private_key = strcat(OTS_private_key, x(ip, :));
    end
    OTS_PRIV(iq + 1, :) = OTS_private_key;
    X(iq + 1, :) = x;
    %
    y = char();
    for ip = 1 : p
        % temp = x[i]
        temp = x(ip, :);
        for j = 1 : 2^w
            % temp = H(I || u32str(q) || u16str(i) || u8str(j) || temp)
            II = strcat(I, qq, lower(dec2hex(ip-1, 4)), lower(dec2hex(j-1, 2)), temp);
            temp = SHA256(II);
        end
        y(ip, :) = temp;
    end
    II = strcat(I, qq, '8080');
    for ip = 1 : p
        II = strcat(II, y(ip, :));
    end
    K = SHA256(II);
    OTS_public_key = strcat(otstype, I, qq, K);
    OTS_PUB_HASH(iq + 1, :) = OTS_public_key;
end
LM_PRIV = OTS_PRIV;
%
% 5.3 LMS Public Key, computing a LMS public key
%
fprintf('computing a LMS public key \n');
%
T = char();
for ir = 2^(h+1)-1 : -1 : 1
    if ir >= 2^h
        II = strcat(I, lower(dec2hex(ir, 8)), '8282', OTS_PUB_HASH(ir - 2^h + 1));
        T(ir, :) = SHA256(II);
    else
        II = strcat(I, lower(dec2hex(ir, 8)), '8383', T(2*ir, :), T(2*ir + 1, :));
        T(ir, :) = SHA256(II);
    end
end
T1 = T(1, :);
% 
LMS_public_key = strcat(type, otstype, I, T1);
%
% 5.4 LMS Signature generation
%
fprintf('computing of a LMS signature \n');
%
% u32str(q) || 





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
% message = '54686520706f77657273206e6f742064656c65676174656420746f2074686520556e69746564205374617465732062792074686520436f6e737469747574696f6e2c206e6f722070726f6869626974656420627920697420746f20746865205374617465732c2061726520726573657276656420746f207468652053746174657320726573706563746976656c792c206f7220746f207468652070656f706c652e0a';

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
LM_time = ending_time - starting_time; % ending time - starting time
% LMOTS_time = cputime - LMOTS_time;
%
fprintf('the computation time is: %f\n', LM_time);
%



