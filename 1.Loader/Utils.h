#pragma once
#include <vector>
#include <string>

// NOTICE: Only semicolons ; at the end. NO bodies.
std::vector<int> UtilsStringToHexEncode(const char* stringValue);
std::string UtilsHexToStringDecode(const std::vector<int>& hexValues);


std::vector<int> UtilsStringToHexEncodeXOR(const char* stringValue, int key);
std::string UtilsHexToStringDecodeXOR(const std::vector<int>& hexValues,int key);


void UtilPayloadXorDecrypt(unsigned char* data, size_t data_len, unsigned char* key, size_t key_len);
int UtilDecryptFileQuoted(unsigned char* buf, int len, unsigned char **newBuff);