#include <cstdio>
#include <cstddef>
#include <span>
#include <optional>
#include <algorithm>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <future>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <array>
#include <variant>
#include <winscard.h>
#include <openssl/evp.h>
#include "aribb61.h"

constexpr uint16_t CA_SYSTEM_ID = 0x0005;

class CardTransaction
{
    CardTransaction(const CardTransaction&) = delete;
    SCARDHANDLE card;
public:
    CardTransaction(SCARDHANDLE card) : card(card) {}
    LONG EndTransaction()
    {
        auto r = SCardEndTransaction(card, SCARD_LEAVE_CARD);
        card = 0;
        return r;
    }
    ~CardTransaction()
    {
        if (card)
        {
            EndTransaction();
        }
    }
};

#ifdef _WIN32
using tstring = std::basic_string<TCHAR, std::char_traits<TCHAR>, std::allocator<TCHAR>>;
#else
using tstring = std::string;
#endif

class CardReader
{
    SCARDCONTEXT context = 0;
    SCARDHANDLE card = 0;
    DWORD activeProtocol = 0;
    CardReader(const CardReader&) = delete;
public:
    CardReader()
    {
    }

    LONG EstablishContext()
    {
        if (context)
        {
            return SCARD_S_SUCCESS;
        }
        return SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &context);
    }

    void Disconnect()
    {
        if (card)
        {
            SCardDisconnect(card, SCARD_UNPOWER_CARD);
            card = 0;
        }
    }

    std::vector<tstring> ListReaders(LONG *r)
    {
        LPTSTR readers = nullptr;
        DWORD size = SCARD_AUTOALLOCATE;
        *r = SCardListReaders(context, nullptr, (LPTSTR)&readers, &size);
        if (*r != SCARD_S_SUCCESS || !readers)
        {
            if (readers)
            {
                SCardFreeMemory(context, readers);
            }
            return {};
        }
        std::vector<tstring> vec;
        auto rr = readers;
        while (*rr)
        {
            vec.push_back(tstring(rr));
            auto k = vec[vec.size() - 1].size();
            rr += vec[vec.size() - 1].size() + 1;
        }
        if (readers)
        {
            SCardFreeMemory(context, readers);
        }
        return vec;
    }

    LONG Connect(LPCTSTR reader)
    {
        LONG result;
        Disconnect();
        result = SCardConnect(context, reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card, &activeProtocol);
        if (result != SCARD_S_SUCCESS)
        {
            return result;
        }
        return SCARD_S_SUCCESS;
    }

    std::optional<CardTransaction> BeginTransaction(LONG* err)
    {
        *err = SCardBeginTransaction(card);
        return std::make_optional(card);
    }

    LONG Transmit(std::span<const uint8_t> sendData, std::span<uint8_t> recvData, DWORD* length)
    {
        auto sendPci = activeProtocol == SCARD_PROTOCOL_T0 ? SCARD_PCI_T0 : SCARD_PCI_T1;
        LONG r;
        for (int i = 0; i < 5; i++)
        {
            *length = static_cast<DWORD>(recvData.size());
            r = SCardTransmit(card, sendPci, sendData.data(), static_cast<DWORD>(sendData.size()), nullptr, recvData.data(), length);
            if (r == SCARD_S_SUCCESS)
            {
                break;
            }
        }
        return r;
    }

    ~CardReader()
    {
        Disconnect();
        if (context)
        {
            SCardReleaseContext(context);
        }
    }
};

class SHA256Hash
{
    EVP_MD_CTX* mdctx;
public:
    SHA256Hash()
    {
        mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    }
    void Update(std::span<const uint8_t> data)
    {
        EVP_DigestUpdate(mdctx, const_cast<PUCHAR>(data.data()), data.size());
    }
    void Final(std::span<uint8_t> output)
    {
        unsigned int len = 32;
        EVP_DigestFinal_ex(mdctx, output.data(), &len);
        EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    }
};

class AES128CTR
{
    EVP_CIPHER_CTX* ctx;
public:
    AES128CTR()
    {
        ctx = EVP_CIPHER_CTX_new();
    }
    void Init(std::array<uint8_t, 16> key, std::array<uint8_t, 16> iv)
    {
        EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key.data(), iv.data());
    }
    void Update(std::span<uint8_t> out, std::span<uint8_t> in)
    {
        int outl = static_cast<int>(out.size());
        EVP_DecryptUpdate(ctx, out.data(), &outl, in.data(), static_cast<int>(in.size()));
    }
    ~AES128CTR()
    {
        EVP_CIPHER_CTX_free(ctx);
    }
};

struct FinishMessage
{
};

struct ECMMessage
{
    std::vector<uint8_t> request;
    std::promise<std::vector<uint8_t>> response;
};

using Message = std::variant<ECMMessage, FinishMessage>;

class CardWorker
{
    enum arib_b61_log_level logLevel;
    std::mutex lock;
    std::condition_variable cv;
    std::queue<Message> queue;
    CardReader reader;
    SHA256Hash sha256;
    Message DequeMessage()
    {
        std::unique_lock guard(lock);
        cv.wait(guard, [this] { return !queue.empty(); });
        Message item = std::move(queue.front());
        queue.pop();
        guard.unlock();
        return item;
    }
    LONG GetKCL(std::array<uint8_t, 32> &kcl)
    {
        uint8_t a0init[8] = {};
        uint8_t apdu2[] = {
            0x90, // CLA
            0xA0, // INS
            0x00, // P1
            0x01, // P2
            0x10, // Lc,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x8A, 0xF7,
            a0init[0], a0init[1], a0init[2], a0init[3], a0init[4], a0init[5], a0init[6], a0init[7],
            0x00, // Le
        };
        uint8_t recv[256] = {};
        DWORD length = 0;
        auto r = reader.Transmit(std::span{ apdu2 }, std::span{ recv }, &length);
        uint8_t master[32] = {
            0x4F, 0x4C, 0x7C, 0xEB, 0x34, 0xFE, 0xB0, 0xA3,
            0x1E, 0x41, 0x19, 0x51, 0xE1, 0x35, 0x15, 0x12,
            0x87, 0xD3, 0x3D, 0x33, 0xD4, 0x9B, 0x4F, 0x52,
            0x05, 0x77, 0xF9, 0xEF, 0xE5, 0x56, 0x1F, 0x32,
        };
        uint8_t a0response[8] = {};
        uint8_t a0hash[32] = {};
        std::copy(recv + 6, recv + 14, a0response);
        std::copy(recv + 14, recv + 14 + 32, a0hash);
        sha256.Update(master);
        sha256.Update(a0init);
        sha256.Update(a0response);
        sha256.Final(kcl);
        uint8_t hash[32] = {};
        sha256.Update(kcl);
        sha256.Update(a0init);
        sha256.Final(hash);
        return r;
    }
    std::vector<uint8_t> ProcessECM(std::vector<uint8_t> &ecm)
    {
        LONG r;
        std::vector<uint8_t> apdu;
        apdu.reserve(ecm.size() + 6);
        apdu.push_back(0x90); // CLA
        apdu.push_back(0x34); // INS
        apdu.push_back(0x00); // P1
        apdu.push_back(0x01); // P2
        apdu.push_back(static_cast<uint8_t>(ecm.size())); // Lc
        apdu.insert(apdu.end(), ecm.begin(), ecm.end());
        apdu.push_back(0x00); // Le
        std::array<uint8_t, 32> kcl;
        uint8_t recv[256] = {};
        auto transaction = reader.BeginTransaction(&r);
        GetKCL(kcl);
        DWORD length;
        reader.Transmit(std::span{ apdu }, std::span{ recv }, &length);
        transaction->EndTransaction();
        if (length < 6 + 32 + 2 || recv[length - 2] != 0x90 || recv[length - 1] != 0x00)
        {
            return {};
        }
        sha256.Update(kcl);
        sha256.Update(std::span(ecm.begin() + 4, ecm.begin() + 27));
        std::vector<uint8_t> hash(32);
        sha256.Final(hash);
        for (int i = 0; i < hash.size(); i++)
        {
            hash[i] ^= recv[6 + i];
        }
        return hash;
    }
    bool InitCard()
    {
        auto result = reader.EstablishContext();
        if (result != SCARD_S_SUCCESS)
        {
            return false;
        }
        auto readers = reader.ListReaders(&result);
        if (result != SCARD_S_SUCCESS)
        {
            return false;
        }
        for (auto&& name : readers)
        {
            if (SendInitCommand(name.c_str()))
            {
                return true;
            }
            reader.Disconnect();
        }
        return false;
    }
    bool SendInitCommand(LPCTSTR name)
    {
        auto result = reader.Connect(name);
        if (result != SCARD_S_SUCCESS)
        {
            return false;
        }
        uint8_t apdu[] = {
            0x90, // CLA
            0x30, // INS
            0x00, // P1
            0x01, // P2
            0x00, // Le
        };
        uint8_t recv[256] = {};
        DWORD length = 0;
        result = reader.Transmit(std::span{ apdu }, std::span{ recv }, &length);
        if (result != SCARD_S_SUCCESS)
        {
            return false;
        }
        if (length < 2)
        {
            return false;
        }
        auto sw1 = recv[length - 2];
        auto sw2 = recv[length - 1];
        if (sw1 != 0x90 || sw2 != 0x00)
        {
            return false;
        }
        auto body = std::span(recv, length - 2);
        if (body.size() < 17)
        {
            return false;
        }
        auto caSystemId = (body[6] << 8) | body[7];
        if (caSystemId != CA_SYSTEM_ID)
        {
            return false;
        }
        // valid card
        return true;
    }
    void DoWork()
    {
        InitCard();
        while (true)
        {
            auto message = DequeMessage();
            if (std::holds_alternative<ECMMessage>(message))
            {
                auto begin = std::chrono::high_resolution_clock::now();
                auto& ecm = std::get<ECMMessage>(message);
                auto resp = ProcessECM(ecm.request);
                auto end = std::chrono::high_resolution_clock::now();
                ecm.response.set_value(resp);
                if (logLevel >= ARIB_B61_LOG_VERBOSE)
                {
                    fprintf(stderr, "ECM proc %lld ms\n", static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count()));
                }
            }
            else if (std::holds_alternative<FinishMessage>(message))
            {
                break;
            }
        }
    }
public:
    CardWorker(enum arib_b61_log_level logLevel) : logLevel(logLevel)
    {
    }
    void SendWorkerMessage(Message message)
    {
        std::lock_guard guard(lock);
        queue.push(std::move(message));
        cv.notify_one();
    }
    static void Work(std::shared_ptr<CardWorker> worker)
    {
        worker->DoWork();
    }
};

class CardWorkerRef
{
    CardWorkerRef(const CardWorkerRef&) = delete;
    std::shared_ptr<CardWorker> worker;
public:
    CardWorkerRef(std::shared_ptr<CardWorker> worker) : worker(worker) {}
    std::future<std::vector<uint8_t>> SendECM(std::vector<uint8_t> ecm)
    {
        std::promise<std::vector<uint8_t>> response;
        auto future = response.get_future();
        worker->SendWorkerMessage(ECMMessage{ std::move(ecm), std::move(response) });
        return future;
    }
    ~CardWorkerRef()
    {
        worker->SendWorkerMessage(FinishMessage{});
    }
};

CardWorkerRef StartCardWorker(enum arib_b61_log_level logLevel)
{
    auto worker = std::make_shared<CardWorker>(logLevel);
    std::thread t(CardWorker::Work, worker);
    t.detach();
    return CardWorkerRef(std::move(worker));
}

struct arib_b61_decoder_params
{
};

enum class SIType
{
    PLT,
    MPT,
    ECM,
    CAT,
    EMM,
};

struct MMTSIBuffer
{
    uint16_t packetId;
    SIType type;
    size_t refCount = 1;
    int version = -1;
    std::vector<uint8_t> buffer;
};

struct Program
{
    uint16_t serviceId;
    uint16_t ecmPID = 0xffff;
    size_t refCount = 1;
    bool mptReceived = false;
    std::unordered_set<uint16_t> scrambledAssets;
};

enum class KeyType
{
    Unknown,
    Even,
    Odd,
};

struct ScrambledAsset
{
    uint16_t ecmPID;
    KeyType keyType = KeyType::Unknown;
    size_t refCount = 1;
};

struct ECM
{
    bool received = false;
    int version = -1;
    std::optional<std::future<std::vector<uint8_t>>> future;
    KeyType keyType = KeyType::Unknown;
    std::array<uint8_t, 16> evenKey;
    std::array<uint8_t, 16> oddKey;
};

struct EncryptedPacket
{
    size_t offset;
    size_t size;
};

class ARIBB61Decoder
{
    enum arib_b61_log_level logLevel;
    CardWorkerRef worker;
    std::vector<uint8_t> tlvBuffer;
    std::vector<uint8_t> outputBuffer;
    std::unordered_map<uint16_t, Program> programs;
    std::unordered_map<uint16_t, MMTSIBuffer> siBuffer;
    std::unordered_map<uint16_t, ScrambledAsset> scrambledAssets;
    std::unordered_map<uint16_t, ECM> ecmList;
    bool strip = false;
    bool stripInvalidData = true;
    bool asyncECM = true;
    AES128CTR aes128ctr;
    size_t initialBufferingSize = 16 * 1024 * 1024;
    bool initialBuffering = true;
    bool received = false;
    std::vector<EncryptedPacket> encryptedPackets;
public:
    ARIBB61Decoder(enum arib_b61_log_level logLevel) : worker(StartCardWorker(logLevel)), logLevel(logLevel)
    {
        tlvBuffer.reserve(32 * 1024 * 1024);
        outputBuffer.reserve(32 * 1024 * 1024);
        siBuffer.emplace(0x0000, MMTSIBuffer{ 0x0000, SIType::PLT });
    }
    void SetInitialBuffering(bool enable)
    {
        if (received)
        {
            return;
        }
        this->initialBuffering = enable;
    }
    void SetStrip(bool enable)
    {
        this->strip = enable;
    }
    void SetStripInvalidData(bool enable)
    {
        this->stripInvalidData = enable;
    }
    void SetAsyncECM(bool enable)
    {
        this->asyncECM = enable;
    }
private:

    void DecryptPendingPackets()
    {
        for (auto&& packet : encryptedPackets)
        {
            ProcessMMTP(std::span(outputBuffer.begin() + packet.offset, packet.size));
        }
        std::vector<EncryptedPacket>().swap(encryptedPackets);
        initialBuffering = false;
    }

    // false: invalid mmtp packet
    bool ProcessMMTP(std::span<uint8_t> mmtpPacket, bool decryptOnly = false)
    {
        auto p = mmtpPacket.begin();
        if (mmtpPacket.end() - p < 1)
        {
            return false;
        }
        auto flags = *p;
        // VVPFER
        auto extensionFlag = flags & 2;
        p += 1;
        if (mmtpPacket.end() - p < 1)
        {
            return false;
        }
        auto payloadType = *p & 0x3f;
        p += 1;
        if (mmtpPacket.end() - p < 2)
        {
            return false;
        }
        auto packetId = static_cast<uint16_t>((p[0] << 8) | p[1]);
        p += 2;
        if (mmtpPacket.end() - p < 4)
        {
            return false;
        }
        p += 4;
        if (mmtpPacket.end() - p < 4)
        {
            return false;
        }
        uint32_t packetSequenceNumber = (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) | (static_cast<uint32_t>(p[2]) << 8) | (static_cast<uint32_t>(p[3]) << 0);
        p += 4;
        auto mmtpPayload = p;
        if (extensionFlag)
        {
            if (mmtpPacket.end() - p < 2)
            {
                return false;
            }
            auto extensionType = (p[0] << 8) | p[1];
            p += 2;
            if (mmtpPacket.end() - p < 2)
            {
                return false;
            }
            auto extensionLength = (p[0] << 8) | p[1];
            p += 2;
            if (mmtpPacket.end() - p < extensionLength)
            {
                return false;
            }
            mmtpPayload = p + extensionLength;
            if (extensionType == 0)
            {
                while (mmtpPayload - p >= 4)
                {
                    auto hdrExtEndFlag = p[0] & 0x80;
                    auto hdrExtType = ((p[0] & 0x7F) << 8) | p[1];
                    auto hdrExtLength = (p[2] << 8) | p[3];
                    p += 4;
                    if (mmtpPayload - p < hdrExtLength)
                    {
                        return false;
                    }
                    if (hdrExtType == 1 && hdrExtLength > 0 && mmtpPayload - p >= 1 && mmtpPacket.end() - mmtpPayload >= 8)
                    {
                        auto control = (p[0] >> 3) & 3;
                        auto hasId = p[0] & 4;
                        auto hasMac = p[0] & 2; // unused
                        auto hasIV = p[0] & 1;
                        auto ivOffset = (hasId ? 1 : 0) + (hasMac ? 2 : 0);
                        if (control == 2 || control == 3)
                        {
                            if (hasIV && hdrExtLength < ivOffset + 16)
                            {
                                // ??
                                hasIV = false;
                            }
                            auto it = scrambledAssets.find(packetId);
                            auto keyType = control == 2 ? KeyType::Even : KeyType::Odd;
                            if (it != scrambledAssets.end())
                            {
                                if (!decryptOnly)
                                {
                                    if (it->second.keyType != keyType)
                                    {
                                        if (logLevel >= ARIB_B61_LOG_VERBOSE)
                                        {
                                            fprintf(stderr, "PID %04x key %s => %s\n", packetId, it->second.keyType == KeyType::Even ? "even" : (it->second.keyType == KeyType::Odd ? "odd" : "unk"), keyType == KeyType::Even ? "even" : (keyType == KeyType::Odd ? "odd" : "unk"));
                                        }
                                    }
                                    it->second.keyType = keyType;
                                }
                                auto ecm = ecmList.find(it->second.ecmPID);
                                if (ecm == ecmList.end())
                                {
                                    if (initialBuffering)
                                    {
                                        encryptedPackets.push_back(EncryptedPacket
                                            {
                                                .offset = static_cast<size_t>(&mmtpPacket[0] - &outputBuffer[0]),
                                                .size = mmtpPacket.size(),
                                            });
                                    }
                                }
                                else if (ecm->second.future || ecm->second.received)
                                {
                                    if (!decryptOnly && (asyncECM || keyType != ecm->second.keyType) && ecm->second.future)
                                    {
                                        auto begin = std::chrono::high_resolution_clock::now();
                                        ecm->second.future->wait();
                                        auto end = std::chrono::high_resolution_clock::now();
                                        if (logLevel >= ARIB_B61_LOG_VERBOSE)
                                        {
                                            fprintf(stderr, "wait ECM %lld ms\n", static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count()));
                                        }
                                        ecm->second.received = true;
                                        auto&& r = ecm->second.future->get();
                                        auto oddKey = r.begin();
                                        auto evenKey = r.begin() + ecm->second.oddKey.size();
                                        if (logLevel >= ARIB_B61_LOG_VERBOSE)
                                        {
                                            fprintf(stderr, "odd: %02x-%02x-%02x-%02x => %02x-%02x-%02x-%02x\n", ecm->second.oddKey[0], ecm->second.oddKey[1], ecm->second.oddKey[2], ecm->second.oddKey[3], oddKey[0], oddKey[1], oddKey[2], oddKey[3]);
                                            fprintf(stderr, "even: %02x-%02x-%02x-%02x => %02x-%02x-%02x-%02x\n", ecm->second.evenKey[0], ecm->second.evenKey[1], ecm->second.evenKey[2], ecm->second.evenKey[3], evenKey[0], evenKey[1], evenKey[2], evenKey[3]);
                                        }
                                        if (std::equal(oddKey, evenKey, ecm->second.oddKey.begin()))
                                        {
                                            if (logLevel >= ARIB_B61_LOG_VERBOSE)
                                            {
                                                fprintf(stderr, "ecm recv, same odd\n");
                                            }
                                            ecm->second.keyType = KeyType::Even;
                                        }
                                        else if (std::equal(evenKey, r.end(), ecm->second.evenKey.begin()))
                                        {
                                            if (logLevel >= ARIB_B61_LOG_VERBOSE)
                                            {
                                                fprintf(stderr, "ecm recv, same even\n");
                                            }
                                            ecm->second.keyType = KeyType::Odd;
                                        }
                                        else if (ecm->second.keyType == KeyType::Unknown)
                                        {
                                            if (keyType == KeyType::Even)
                                            {
                                                ecm->second.keyType = KeyType::Odd;
                                            }
                                            else
                                            {
                                                ecm->second.keyType = KeyType::Even;
                                            }
                                        }
                                        std::copy(oddKey, evenKey, ecm->second.oddKey.begin());
                                        std::copy(evenKey, r.end(), ecm->second.evenKey.begin());
                                        ecm->second.future = std::nullopt;
                                    }
                                    std::array<uint8_t, 16> iv{};
                                    if (hasIV)
                                    {
                                        std::copy(p + ivOffset, p + ivOffset + 16, iv.begin());
                                    }
                                    else
                                    {
                                        iv[0] = packetId >> 8;
                                        iv[1] = packetId & 0xff;
                                        iv[2] = packetSequenceNumber >> 24;
                                        iv[3] = packetSequenceNumber >> 16;
                                        iv[4] = packetSequenceNumber >> 8;
                                        iv[5] = packetSequenceNumber >> 0;
                                    }
                                    aes128ctr.Init(keyType == KeyType::Even ? ecm->second.evenKey : ecm->second.oddKey, iv);
                                    auto mmtpData = std::span(mmtpPayload + 8, mmtpPacket.end());
                                    aes128ctr.Update(mmtpData, mmtpData);
                                    p[0] &= ~(3 << 3); // remove scramble control bits
                                    auto timedFlag = mmtpPayload[2] & 8;
                                    auto aggregationFlag = mmtpPayload[2] & 1;
                                    if (timedFlag && !aggregationFlag)
                                    {
                                        for (int i = 0; i < 14; i++)
                                        {
                                            if (mmtpData[i])
                                            {
                                                if (logLevel >= ARIB_B61_LOG_VERBOSE)
                                                {
                                                    fprintf(stderr, "broken\n");
                                                }
                                                break;
                                            }
                                        }
                                    }
                                    else if (timedFlag)
                                    {
                                        for (int i = 2; i < 16; i++)
                                        {
                                            if (mmtpData[i])
                                            {
                                                if (logLevel >= ARIB_B61_LOG_VERBOSE)
                                                {
                                                    fprintf(stderr, "broken\n");
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            else if (initialBuffering)
                            {
                                encryptedPackets.push_back(EncryptedPacket
                                    {
                                        .offset = static_cast<size_t>(&mmtpPacket[0] - &outputBuffer[0]),
                                        .size = mmtpPacket.size(),
                                    });
                            }
                        }
                    }
                    p += hdrExtLength;
                }
            }
        }
        if (decryptOnly)
        {
            return true;
        }
        if (payloadType == 2) // SI
        {
            auto entry = siBuffer.find(packetId);
            if (entry == siBuffer.end())
            {
                return true;
            }
            MMTSIBuffer& si = entry->second;
            if (mmtpPacket.end() - mmtpPayload < 2)
            {
                return false;
            }
            auto fragmentationIndicator = mmtpPayload[0] >> 6;
            auto mmtpData = mmtpPayload + 2;
            if (fragmentationIndicator == 0 || fragmentationIndicator == 1)
            {
                si.buffer.resize(0);
            }
            if (fragmentationIndicator == 0)
            {
                auto payload = std::span(mmtpData, mmtpPacket.end());
                ProcessSIMessage(si, payload);
                return true;
            }
            si.buffer.insert(si.buffer.end(), mmtpData, mmtpPacket.end());
            if (fragmentationIndicator == 3)
            {
                auto payload = std::span(si.buffer.begin(), si.buffer.end());
                ProcessSIMessage(si, payload);
                si.buffer.resize(0);
                return true;
            }
        }
        return true;
    }

    void ProcessSIMessage(MMTSIBuffer& si, std::span<const uint8_t> payload)
    {
        auto p = payload.begin();
        if (payload.end() - p < 5)
        {
            return;
        }
        auto messageId = (p[0] << 8) | p[1];
        auto version = p[2];
        size_t length = (static_cast<size_t>(p[3]) << 8) | static_cast<size_t>(p[4]);
        p += 5;
        if (messageId == 0 || messageId == 0x8003)
        {
            if (payload.end() - p < 2)
            {
                return;
            }
            length <<= 16;
            length |= (static_cast<size_t>(p[0]) << 8) | static_cast<size_t>(p[1]);
            p += 2;
        }
        if (static_cast<size_t>(payload.end() - p) < length)
        {
            return;
        }
        auto messagePayload = std::span(p, p + length);
        if (si.type == SIType::PLT || si.type == SIType::MPT)
        {
            if (messageId != 0) // shall be PA message
            {
                return;
            }
            ProcessPAMessage(si, messagePayload);
        }
        if (si.type == SIType::ECM)
        {
            ProcessM2Message(si, messagePayload);
        }
    }

    void ProcessM2Message(MMTSIBuffer& si, std::span<const uint8_t> payload)
    {
        auto p = payload.begin();
        if (payload.end() - p < 3)
        {
            return;
        }
        auto tableId = p[0];
        auto sectionLength = ((p[1] << 8) | p[2]) & 0xfff;
        p += 3;
        if (payload.end() - p < sectionLength)
        {
            return;
        }
        auto sectionPayload = std::span(p, p + sectionLength - 4);
        uint32_t crc32 = (static_cast<uint32_t>(p[sectionLength - 4]) << 24) | (static_cast<uint32_t>(p[sectionLength - 3]) << 16) | (static_cast<uint32_t>(p[sectionLength - 2]) << 8) | (static_cast<uint32_t>(p[sectionLength - 1]) << 0);
        if (si.type == SIType::ECM && tableId == 0x82) // 0x83: unused
        {
            ProcessECM(si, sectionPayload);
        }
    }

    void ProcessECM(MMTSIBuffer& si, std::span<const uint8_t> payload)
    {
        auto p = payload.begin();
        if (payload.end() - p < 2 + 1 + 1 + 1)
        {
            return;
        }
        auto ecm = ecmList.find(si.packetId);
        if (ecm == ecmList.end())
        {
            return;
        }
        auto version = (p[2] >> 1) & 0x1f;
        auto currentNextIndicator = p[2] & 1;
        if (!currentNextIndicator)
        {
            return;
        }
        if (ecm->second.version == version)
        {
            return;
        }
        ecm->second.version = version;
        p += 2 + 1 + 1 + 1;
        std::vector<uint8_t> ecmData(p, payload.end());
        auto future = worker.SendECM(std::move(ecmData));
        ecm->second.future = std::move(future);
        if (!initialBuffering)
        {
            return;
        }
        for (auto&& program : programs)
        {
            if (!program.second.mptReceived)
            {
                return;
            }
            auto it = ecmList.find(program.second.ecmPID);
            if (it == ecmList.end())
            {
                return;
            }
            if (!it->second.received && !it->second.future)
            {
                return;
            }
        }
        DecryptPendingPackets();
    }

    void ProcessPAMessage(MMTSIBuffer& si, std::span<const uint8_t> payload)
    {
        auto p = payload.begin();
        if (payload.end() - p < 1)
        {
            return;
        }
        auto numberOfTables = p[0];
        if (numberOfTables != 0)
        {
            return;
        }
        p++;
        if (payload.end() - p < 4)
        {
            return;
        }
        auto tableId = p[0];
        auto version = p[1];
        auto length = (p[2] << 8) | p[3];
        if (si.version == version)
        {
            return;
        }
        p += 4;
        if (payload.end() - p < length)
        {
            return;
        }
        si.version = version;
        auto table = std::span(p, p + length);
        if (si.type == SIType::PLT && tableId == 0x80)
        {
            ProcessPLT(si, table);
            return;
        }
        if (si.type == SIType::MPT && tableId == 0x20)
        {
            ProcessMPT(si, table);
            return;
        }
    }

    void ProcessPLT(MMTSIBuffer& si, std::span<const uint8_t> payload)
    {
        auto p = payload.begin();
        if (payload.end() - p < 1)
        {
            return;
        }
        auto numOfPackage = p[0];
        p++;
        for (auto&& e : programs)
        {
            e.second.refCount = 0;
        }
        for (int i = 0; i < numOfPackage; i++)
        {
            if (payload.end() - p < 1)
            {
                return;
            }
            auto mmtPackageIdLength = p[0];
            p++;
            if (payload.end() - p < mmtPackageIdLength)
            {
                return;
            }
            if (mmtPackageIdLength != 2)
            {
                return;
            }
            auto serviceId = (p[0] << 8) | p[1];
            p += mmtPackageIdLength;
            if (payload.end() - p < 1)
            {
                return;
            }
            auto locationType = p[0];
            p++;
            if (locationType != 0x00)
            {
                return;
            }
            if (payload.end() - p < 2)
            {
                return;
            }
            auto packetId = static_cast<uint16_t>((p[0] << 8) | p[1]);
            p += 2;
            auto it = programs.find(packetId);
            if (it != programs.end())
            {
                it->second.serviceId = serviceId;
                it->second.refCount = 1;
            }
            else
            {
                programs.emplace(packetId, Program{ static_cast<uint16_t>(serviceId) });
                siBuffer.emplace(packetId, MMTSIBuffer{ packetId, SIType::MPT });
            }
        }
        for (auto it = programs.begin(); it != programs.end(); )
        {
            if (it->second.refCount == 0)
            {
                RemoveProgram(it);
                it = programs.erase(it);
            }
            else
            {
                it++;
            }
        }
        // num_of_ip_delivery...
    }

    void ProcessMPT(MMTSIBuffer& si, std::span<const uint8_t> payload)
    {
        auto program = programs.find(si.packetId);
        if (program == programs.end())
        {
            return;
        }
        auto p = payload.begin();
        if (payload.end() - p < 1)
        {
            return;
        }
        auto mptMode = p[0] & 3;
        p++;
        if (mptMode != 0)
        {
            return;
        }
        if (payload.end() - p < 1)
        {
            return;
        }
        auto mmtPackageIdLength = p[0];
        p += 1;
        if (payload.end() - p < mmtPackageIdLength)
        {
            return;
        }
        if (mmtPackageIdLength != 2)
        {
            return;
        }
        p += mmtPackageIdLength;
        if (payload.end() - p < 2)
        {
            return;
        }
        auto mptDescriptorsLength = (p[0] << 8) | p[1];
        p += 2;
        if (payload.end() - p < mptDescriptorsLength)
        {
            return;
        }
        auto descEnd = p + mptDescriptorsLength;
        auto prevECMPID = program->second.ecmPID;
        program->second.ecmPID = 0xffff;
        program->second.mptReceived = true;
        while (descEnd - p >= 3)
        {
            auto tag = (p[0] << 8) | p[1];
            auto length = p[2];
            p += 3;
            if (descEnd - p < length)
            {
                return;
            }
            switch (tag)
            {
            case 0x8004:
            {
                if (length < 5)
                {
                    return;
                }
                auto caSystemId = (p[0] << 8) | p[1];
                if (caSystemId != CA_SYSTEM_ID)
                {
                    break;
                }
                auto locationType = p[2];
                if (locationType != 0x00)
                {
                    return;
                }
                auto packetId = (p[3] << 8) | p[4];
                program->second.ecmPID = packetId;
                break;
            }
            }
            p += length;
        }
        p = descEnd;
        if (payload.end() - p < 1)
        {
            return;
        }
        auto numberOfAssets = p[0];
        p++;
        for (auto&& s : program->second.scrambledAssets)
        {
            auto it = this->scrambledAssets.find(s);
            if (it != this->scrambledAssets.end())
            {
                it->second.refCount--;
            }
        }
        program->second.scrambledAssets.clear();
        while (payload.end() - p >= 1 + 4 + 1)
        {
            auto identifierType = p[0];
            auto assetIdLength = p[5];
            p += 1 + 4 + 1;
            if (payload.end() - p < assetIdLength)
            {
                break;
            }
            p += assetIdLength;
            if (payload.end() - p < 4)
            {
                break;
            }
            // asset_type
            p += 4;
            if (payload.end() - p < 1)
            {
                break;
            }
            // reserved, asset_clock_relation_flag
            p++;
            if (payload.end() - p < 1)
            {
                break;
            }
            auto locationCount = p[0];
            p++;
            if (locationCount != 1)
            {
                break;
            }
            if (payload.end() - p < 3)
            {
                break;
            }
            auto locationType = p[0];
            if (locationType != 0x00)
            {
                break;
            }
            auto packetId = (p[1] << 8) | p[2];
            p += 3;
            if (payload.end() - p < 2)
            {
                break;
            }
            auto assetDescriptorsLength = (p[0] << 8) | p[1];
            p += 2;
            if (payload.end() - p < assetDescriptorsLength)
            {
                break;
            }
            auto descEnd = p + assetDescriptorsLength;
            bool scrambled = true;
            while (descEnd - p >= 3)
            {
                auto tag = (p[0] << 8) | p[1];
                auto length = p[2];
                p += 3;
                if (descEnd - p < length)
                {
                    break;
                }
                switch (tag)
                {
                case 0x8004:
                {
                    if (length < 5)
                    {
                        break;
                    }
                    auto caSystemId = (p[0] << 8) | p[1];
                    if (caSystemId != CA_SYSTEM_ID)
                    {
                        break;
                    }
                    auto locationType = p[2];
                    if (locationType != 0x00)
                    {
                        break;
                    }
                    auto ecmPacketId = (p[3] << 8) | p[4];
                    if (ecmPacketId == 0xffff)
                    {
                        scrambled = false;
                    }
                    break;
                }
                }
                p += length;
            }
            if (scrambled)
            {
                AddScrambledAsset(packetId, program->second.ecmPID);
                program->second.scrambledAssets.emplace(packetId);
            }
            p = descEnd;
        }
        CleanupScrambledAsset();
        if (prevECMPID != program->second.ecmPID)
        {
            AddECM(program->second.ecmPID);
            RemoveECM(prevECMPID);
        }
    }

    void AddScrambledAsset(uint16_t packetId, uint16_t ecmPID)
    {
        auto it = scrambledAssets.find(packetId);
        if (it == scrambledAssets.end())
        {
            scrambledAssets.emplace(packetId, ScrambledAsset{ ecmPID });
        }
        else
        {
            it->second.refCount += 1;
            it->second.ecmPID = ecmPID;
        }
    }

    void CleanupScrambledAsset()
    {
        std::erase_if(scrambledAssets, [](const auto& x) { return x.second.refCount == 0; });
    }

    void RemoveProgram(std::unordered_map<uint16_t, Program>::iterator it)
    {
        auto e = siBuffer.find(it->first);
        if (e == siBuffer.end())
        {
            return;
        }
        RemoveECM(it->second.ecmPID);
        siBuffer.erase(it->first);
    }

    void AddECM(uint16_t pid)
    {
        if (!pid || pid == 0xffff)
        {
            return;
        }
        auto e = siBuffer.find(pid);
        if (e == siBuffer.end())
        {
            siBuffer.emplace(pid, MMTSIBuffer{ pid, SIType::ECM });
            ecmList.emplace(pid, ECM{ });
            return;
        }
        else
        {
            e->second.refCount++;
        }
    }

    void RemoveECM(uint16_t pid)
    {
        if (!pid || pid == 0xffff)
        {
            return;
        }
        auto e = siBuffer.find(pid);
        if (e == siBuffer.end())
        {
            return;
        }
        e->second.refCount--;
        if (e->second.refCount == 0)
        {
            siBuffer.erase(e);
        }
    }

public:
    void Put(std::span<const uint8_t> buffer)
    {
        received = true;
        tlvBuffer.insert(tlvBuffer.end(), buffer.begin(), buffer.end());
        auto syncBytePos = tlvBuffer.begin();
        if (stripInvalidData)
        {
            outputBuffer.insert(outputBuffer.end(), tlvBuffer.begin(), syncBytePos);
        }
        while (tlvBuffer.end() - syncBytePos >= 3)
        {
            auto syncByte = syncBytePos[0];
            if (syncByte != 0x7F)
            {
                auto nextSyncBytePos = std::find(syncBytePos, tlvBuffer.end(), 0x7F);
                if (stripInvalidData)
                {
                    outputBuffer.insert(outputBuffer.end(), syncBytePos, nextSyncBytePos);
                }
                syncBytePos = nextSyncBytePos;
                continue;
            }
            auto packetType = syncBytePos[1];
            if (packetType != 0x02 && packetType != 0x03 && packetType != 0xfe && packetType != 0xff)
            {
                auto nextSyncBytePos = std::find(syncBytePos + 1, tlvBuffer.end(), 0x7F);
                if (stripInvalidData)
                {
                    outputBuffer.insert(outputBuffer.end(), syncBytePos, nextSyncBytePos);
                }
                syncBytePos = nextSyncBytePos;
                continue;
            }
            auto packetLength = (syncBytePos[2] << 8) | syncBytePos[3];
            if (tlvBuffer.end() - (syncBytePos + 4) < packetLength)
            {
                break;
            }
            auto packetEnd = syncBytePos + 4 + packetLength;
            switch (packetType)
            {
            case 0x02: // IPv6, clock (NTP)
            case 0xfe: // SI
                outputBuffer.insert(outputBuffer.end(), syncBytePos, packetEnd);
                break;
            case 0xff: // null
                if (!strip)
                {
                    outputBuffer.insert(outputBuffer.end(), syncBytePos, packetEnd);
                }
                break;
            case 0x03: // IPv6 compressed
            {
                auto compressed = syncBytePos + 4;
                auto cidHeaderType = compressed + 3 <= tlvBuffer.end() ? compressed[2] : 0;
                if (cidHeaderType != 0x60 && cidHeaderType != 0x61)
                {
                    auto nextSyncBytePos = std::find(syncBytePos, tlvBuffer.end(), 0x7F);
                    if (stripInvalidData)
                    {
                        outputBuffer.insert(outputBuffer.end(), syncBytePos, nextSyncBytePos);
                    }
                    syncBytePos = nextSyncBytePos;
                    continue;
                }
                auto cid = (compressed[0] << 4) | (compressed[1] >> 4);
                auto sn = compressed[1] & 0xF;
                switch (cidHeaderType)
                {
                case 0x60: // IPv6+UDP header without length
                {
                    auto payloadBegin = compressed + 3 + 38 + 4;
                    if (payloadBegin > tlvBuffer.end())
                    {
                        auto nextSyncBytePos = std::find(syncBytePos, tlvBuffer.end(), 0x7F);
                        if (stripInvalidData)
                        {
                            outputBuffer.insert(outputBuffer.end(), syncBytePos, nextSyncBytePos);
                        }
                        syncBytePos = nextSyncBytePos;
                        continue;
                    }
                    auto packetSize = packetEnd - syncBytePos;
                    outputBuffer.insert(outputBuffer.end(), syncBytePos, packetEnd);
                    auto outputPacket = std::span(outputBuffer.end() - packetSize, outputBuffer.end());
                    auto payload = std::span(outputPacket.begin() + (payloadBegin - syncBytePos), outputPacket.end());
                    ProcessMMTP(payload);
                    break;
                }
                case 0x61: // compressed (payload only)
                {
                    auto payloadBegin = compressed + 3;
                    outputBuffer.insert(outputBuffer.end(), syncBytePos, packetEnd);
                    auto packetSize = packetEnd - syncBytePos;
                    auto outputPacket = std::span(outputBuffer.end() - packetSize, outputBuffer.end());
                    auto payload = std::span(outputPacket.begin() + (payloadBegin - syncBytePos), outputPacket.end());
                    ProcessMMTP(payload);
                    break;
                }
                }
            }
            }
            syncBytePos = packetEnd;
        }
        tlvBuffer.erase(tlvBuffer.begin(), syncBytePos);
    }

    void GetHead(const uint8_t** ptr, size_t* size)
    {
        if (initialBuffering)
        {
            *ptr = nullptr;
            *size = 0;
            return;
        }
        *ptr = outputBuffer.data();
        *size = outputBuffer.size();
    }

    void Consume()
    {
        if (initialBuffering)
        {
            return;
        }
        outputBuffer.resize(0);
    }

    void Finish()
    {
        initialBuffering = false;
        outputBuffer.insert(outputBuffer.end(), tlvBuffer.begin(), tlvBuffer.end());
        tlvBuffer.erase(tlvBuffer.begin(), tlvBuffer.end());
    }
};

#ifdef _USRDLL
#define DLL_EXPORT __declspec(dllexport)
#else
#ifndef _MSC_VER
#define DLL_EXPORT __attribute__((visibility ("default")))
#else
#define DLL_EXPORT
#endif
#endif
#ifdef __cplusplus
extern "C"
{
#endif

DLL_EXPORT enum arib_b61_status arib_b61_decoder_create(struct arib_b61_decoder **decoder, enum arib_b61_log_level level)
{
    *decoder = reinterpret_cast<struct arib_b61_decoder*>(new ARIBB61Decoder(level));
    return ARIB_B61_SUCCESS;
}
DLL_EXPORT enum arib_b61_status arib_b61_decoder_put(struct arib_b61_decoder* decoder, const void* data, size_t size)
{
    auto dec = reinterpret_cast<ARIBB61Decoder*>(decoder);
    dec->Put(std::span(static_cast<const uint8_t*>(data), size));
    return ARIB_B61_SUCCESS;
}
DLL_EXPORT enum arib_b61_status arib_b61_decoder_get_buffer(struct arib_b61_decoder* decoder, const void** data, size_t* size)
{
    auto dec = reinterpret_cast<ARIBB61Decoder*>(decoder);
    dec->GetHead(reinterpret_cast<const uint8_t**>(data), size);
    return ARIB_B61_SUCCESS;
}
DLL_EXPORT enum arib_b61_status arib_b61_decoder_consume_buffer(struct arib_b61_decoder* decoder)
{
    auto dec = reinterpret_cast<ARIBB61Decoder*>(decoder);
    dec->Consume();
    return ARIB_B61_SUCCESS;
}
DLL_EXPORT enum arib_b61_status arib_b61_decoder_finish(struct arib_b61_decoder* decoder)
{
    auto dec = reinterpret_cast<ARIBB61Decoder*>(decoder);
    dec->Finish();
    return ARIB_B61_SUCCESS;
}
DLL_EXPORT void arib_b61_decoder_set_initial_buffering(struct arib_b61_decoder* decoder, int enable)
{
    auto dec = reinterpret_cast<ARIBB61Decoder*>(decoder);
    dec->SetInitialBuffering(enable);
}
DLL_EXPORT void arib_b61_decoder_set_strip(struct arib_b61_decoder* decoder, int enable)
{
    auto dec = reinterpret_cast<ARIBB61Decoder*>(decoder);
    dec->SetStrip(enable);
}
DLL_EXPORT void arib_b61_decoder_set_strip_invalid_data(struct arib_b61_decoder* decoder, int enable)
{
    auto dec = reinterpret_cast<ARIBB61Decoder*>(decoder);
    dec->SetStripInvalidData(enable);
}
DLL_EXPORT void arib_b61_decoder_set_async_ecm(struct arib_b61_decoder* decoder, int enable)
{
    auto dec = reinterpret_cast<ARIBB61Decoder*>(decoder);
    dec->SetAsyncECM(enable);
}
DLL_EXPORT void arib_b61_decoder_release(struct arib_b61_decoder** decoder)
{
    if (!*decoder)
    {
        return;
    }
    auto dec = reinterpret_cast<ARIBB61Decoder*>(*decoder);
    delete dec;
    *decoder = nullptr;
}
#ifdef __cplusplus
}
#endif
