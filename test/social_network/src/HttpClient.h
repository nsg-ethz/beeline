#ifndef SOCIAL_NETWORK_MICROSERVICES_HTTPCLIENT_H
#define SOCIAL_NETWORK_MICROSERVICES_HTTPCLIENT_H

#include <limits>
#include <cstdlib>
#include <sstream>
#include <boost/algorithm/string.hpp>

#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TSSLSocket.h>
#include <thrift/transport/TTransport.h>
#include <thrift/transport/TTransportUtils.h>
#include <thrift/transport/THttpClient.h>
#include <thrift/transport/THttpTransport.h>
#include <thrift/stdcxx.h>
#include <nlohmann/json.hpp>
#include "logger.h"
#include "GenericClient.h"
#include "HttpClient.h"

using std::string;

using apache::thrift::transport::THttpClient;
using apache::thrift::transport::TTransportException;

class HttpClient : public THttpClient {
public:
    HttpClient(std::shared_ptr<TTransport> transport,
                    std::string host, std::string path)
        : THttpClient(transport, host, path) {}

    void flush() override {
        // TTransport::resetConsumedMessageSize();

        // Fetch the contents of the write buffer
        uint8_t* buf;
        uint32_t len;
        writeBuffer_.getBuffer(&buf, &len);

        // Construct the HTTP header
        std::ostringstream h;
        h << "POST " << path_ << " HTTP/1.1" << CRLF << "Host: " << host_ << CRLF
          << "Content-Type: application/x-thrift" << CRLF << "Content-Length: " << len << CRLF
          << "Accept: application/x-thrift" << CRLF << "User-Agent: Thrift/" << PACKAGE_VERSION
          << " (C++/THttpClient)" << CRLF << "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3N1ZXIiOiJiZWVsaW5lIn0.K37-whsn_HoSEXeaITzeK2YmMGg7ylr3STNn6M7_Wys" << CRLF << CRLF;
        string header = h.str();

        if (header.size() > (std::numeric_limits<uint32_t>::max)())
          throw TTransportException("Header too big");
        // Write the header, then the data, then flush
        transport_->write((const uint8_t*)header.c_str(), static_cast<uint32_t>(header.size()));
        transport_->write(buf, len);
        transport_->flush();

        // Reset the buffer and header variables
        writeBuffer_.resetBuffer();
        readHeaders_ = true;
    }

};

#endif //SOCIAL_NETWORK_MICROSERVICES_HTTPCLIENT_H
