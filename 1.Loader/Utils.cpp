#include "Utils.h"

#include <cstring>

// The code body lives HERE.
std::vector<int> UtilsStringToHexEncode(const char* stringValue) {
    if (stringValue == nullptr) return {};
    std::vector<int> hexVector;
    size_t length = std::strlen(stringValue);
    hexVector.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        hexVector.push_back(static_cast<int>(static_cast<unsigned char>(stringValue[i])));
    }
    return hexVector;
}

std::string UtilsHexToStringDecode(const std::vector<int>& hexValues) {
    std::string result;
    result.reserve(hexValues.size());
    for (int value : hexValues) {
        if (value > 0) result += static_cast<char>(value);
    }
    return result;
}

std::vector<int> UtilsStringToHexEncodeXOR(const char* stringValue, int key) {
    if (stringValue == nullptr) return {};
    std::vector<int> hexVector;
    size_t length = std::strlen(stringValue);
    hexVector.reserve(length);
    for (size_t i = 0; i < length; ++i) {

        hexVector.push_back(static_cast<int>(static_cast<unsigned char>(stringValue[i] ^ key)));
    }
    return hexVector;
}

std::string UtilsHexToStringDecodeXOR(const std::vector<int>& hexValues, int key) {
    std::string result;
    result.reserve(hexValues.size());
    for (int value : hexValues) {
        if (value > 0) result += static_cast<char>(value^key);
    }
    return result;
}

void UtilPayloadXorDecrypt(unsigned char* data, size_t data_len, unsigned char* key, size_t key_len) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

int UtilDecryptFileQuoted(unsigned char* buf, int len, unsigned char** newBuff) {
    if (!buf || len <= 0 || !newBuff) return 0;

    // Allocate memory: the binary size is exactly half the character count
    // (excluding any whitespace we might skip).
    *newBuff = (unsigned char*)malloc(len / 2 + 1);
    if (!*newBuff) return 0;
    memset(*newBuff, 0, len / 2 + 1);
    int writeIdx = 0;
    unsigned char msbChar = 0;
    bool waitingForLsb = false;

    for (int i = 0; i < len; ++i) {
        unsigned char c = buf[i];

        // 1. Skip formatting characters that might be in the buffer
        // (Newlines, Carriage Returns, Spaces, and literal double-quotes)
        if (c <= 32 || c == '"' || c == '\\') continue;

        if (!waitingForLsb) {
            // First character of the pair (High Nibble)
            msbChar = c;
            waitingForLsb = true;
        }
        else {
            // Second character of the pair (Low Nibble)
            unsigned char msb = msbChar % 16;
            unsigned char lsb = c % 16;

            // Reconstruct original byte
            (*newBuff)[writeIdx++] = (unsigned char)((msb << 4) | lsb);
            waitingForLsb = false;
        }
    }

    return writeIdx;
}