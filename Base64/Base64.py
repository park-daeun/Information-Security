#!/usr/bin/env python
# coding: utf-8

# In[1]:



#    32171550 박다은
    
#    정보보호개론
#    Base64 Encoding & Decoding
    


# In[2]:


base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


# In[3]:


def encoding(s):
    value = []; i = 0
    while i < len(s):
        value.append((ord(s[i]) >> 2) & 0x3f)
        value.append(((ord(s[i]) & 0x3) << 4) | (ord(s[i+1]) & 0xf0) >> 4)
        value.append(((ord(s[i+1]) & 0xf) << 2) | (ord(s[i+2]) >> 6) & 0x3)
        value.append(ord(s[i+2]) & 0x3f)
        i = i + 3
    
    out = ""
    for j in value:
        out = out + base64[j]
    print("Encoding: ",out)
    
    return out


# In[4]:


def decoding(s):
    value = []; i = 0
    while i < len(s):
        value.append((base64.find(s[i]) << 2) | ((base64.find(s[i+1]) & 0x30) >> 4))
        value.append(((base64.find(s[i+1]) & 0xf) << 4) | ((base64.find(s[i+2]) & 0x3c) >> 2))
        value.append(((base64.find(s[i+2]) & 0x3) << 6) | base64.find(s[i+3]))
        i = i + 4
        
    out = ""
    for j in value:
        out = out + chr(j)
    print("Decoding: ",out)
    
    return out


# In[5]:


#input 파일 열기
in_f = open('input.txt','r')
in_c = in_f.readline()
print("Original Text: ",in_c,"\n")

#encoding
en_f = open('en_output.txt', 'w')
en_f.write(encoding(in_c))

#decoding
de_f = open('de_output.txt', 'w')
de_f.write(decoding(in_c))

in_f.close()
en_f.close()
de_f.close()

