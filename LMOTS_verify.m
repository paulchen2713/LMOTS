%
% Leighton-Micali one-time signatures
%
% clear all;
clc;
LMOTS_time=cputime;
%
% generating a private key
%
fprintf('\ngenerating a private key:\n');
q='00000005';
I='61a5d57d37f5e46bfb7520806b07a1b8';
otstype='LMOTS_SHA256_N32_W1';
if strcmp(otstype,'LMOTS_SHA256_N32_W1')==1
    n=32;
    p=265;
    w=1;
    ls=7;
elseif strcmp(otstype,'LMOTS_SHA256_N32_W2')==1
    n=32;
    p=133;
    w=2;
    ls=6;
elseif strcmp(otstype,'LMOTS_SHA256_N32_W4')==1
    n=32;
    p=67;
    w=4;
    ls=4;
elseif strcmp(otstype,'LMOTS_SHA256_N32_W8')==1
    n=32;
    p=34;
    w=8;
    ls=0;
end
%
x=char();
for ip=1:p
    for in=1:n
        xx=rand(1,8);
        xx=xx>0.5;
        xx=char(xx+48);
        x(ip,(in-1)*2+1:in*2)=lower(dec2hex(bin2dec(xx),2));
    end
end
%
LMOTS_private_key=strcat(otstype,I,q);
for ip=1:p
    LMOTS_private_key=strcat(LMOTS_private_key,x(ip,:));
end
%
% generating a ont-time signature public key
%
fprintf('\ngenerating a ont-time signature public key:\n');
y=char();
for ip=1:p
    temp=x(ip,:);
    for j=1:2^w
        II=strcat(I,q,lower(dec2hex(ip-1,4)),lower(dec2hex(j-1,2)),temp);
        temp=SHA256(II);
    end
    y(ip,:)=temp;
end
II=strcat(I,q,'8080');
for ip=1:p
    II=strcat(II,y(ip,:));
end
K=SHA256(II);
%
LMOTS_public_key=strcat(otstype,I,q,K);
%
% signature generation
%
fprintf('\nsignature generation:\n');
C=char();
for in=1:n
    xx=rand(1,8);
    xx=xx>0.5;
    xx=char(xx+48);
    C(1,(in-1)*2+1:in*2)=lower(dec2hex(bin2dec(xx),2));
end
%
message='54686520706f77657273206e6f742064656c65676174656420746f2074686520556e69746564205374617465732062792074686520436f6e737469747574696f6e2c206e6f722070726f6869626974656420627920697420746f20746865205374617465732c2061726520726573657276656420746f207468652053746174657320726573706563746976656c792c206f7220746f207468652070656f706c652e0a';
%
II=strcat(I,q,'8181',C,message);
Q=SHA256(II);
y=char();
QQ=strcat(Q,cksm(Q,n,w,ls));
for ip=1:p
%     QQ=strcat(Q,cksm(Q,n,w,ls));
    a=coef(QQ,ip-1,w);
    temp=x(ip,:);
    for j=1:a
        II=strcat(I,q,lower(dec2hex(ip-1,4)),lower(dec2hex(j-1,2)),temp);
        temp=SHA256(II);
    end
    y(ip,:)=temp;
end
%
LMOTS_signature=strcat(otstype,C);
for ip=1:p
    LMOTS_signature=strcat(LMOTS_signature,y(ip,:));
end
%
% signature verification
%
fprintf('\nsignature verification:\n');
II=strcat(I,q,'8181',C,message);
Q=SHA256(II);
z=char();
QQ=strcat(Q,cksm(Q,n,w,ls));
for ip=1:p
%     QQ=strcat(Q,cksm(Q,n,w,ls));
    a=coef(QQ,ip-1,w);
    temp=y(ip,:);
    for j=a+1:2^w
        II=strcat(I,q,lower(dec2hex(ip-1,4)),lower(dec2hex(j-1,2)),temp);
        temp=SHA256(II);
    end
    z(ip,:)=temp;
end
%
II=strcat(I,q,'8080');
for ip=1:p
    II=strcat(II,z(ip,:));
end
Kc=SHA256(II);
%
if strcmp(K,Kc)==1
    fprintf('\nVALID\n');
else
    fprintf('\nINVALID\n');
end
LMOTS_time=cputime-LMOTS_time;




