#include "TurnThread.h"
#include <thread>
#include <base/ovcrypto/message_digest.h>
#include "modules/ice/stun/attributes/stun_attributes.h"

TurnThread::TurnThread()
{
  std::thread(&TurnThread::run, this).detach();
}

TurnThread& TurnThread::GetInstance()
{
  static TurnThread theThread;
  return theThread;
}

void TurnThread::addPort(const std::shared_ptr<PhysicalPort>& port)
{
  std::unique_lock<std::mutex> lock(mutex);
	portMap[port->GetAddress()] = port;
}

std::shared_ptr<TurnThread::IceSession> TurnThread::createTurnSession(const ov::SocketAddress& localAddress, const ov::SocketAddress& turnAddress, const std::string& turnUser, const std::string turnPassword)
{
  auto session = std::make_shared<IceSession>();
  session->localAddr = localAddress;
  session->turnAddress = turnAddress;
  session->user = turnUser;
  session->password = turnPassword;

  {
    std::unique_lock<std::mutex> lock(mutex);
    /*if (curPort == portMap.end() || ++curPort == portMap.end())
      curPort = portMap.begin();

    if (curPort != portMap.end()) {
      session->localPort = curPort->second;
    }*/
    decltype(portMap.end()) it = portMap.begin();
    for (; it != portMap.end(); ++it) {
      ov::SocketAddress icePortAddr = it->first;
      if ((icePortAddr.GetIpAddress() == "0.0.0.0" || icePortAddr.GetIpAddress() == localAddress.GetIpAddress()) &&
					icePortAddr.Port() == localAddress.Port()) {
				break;
			}
    }
    if (it == portMap.end() || ++it == portMap.end())
      it = portMap.begin();

    if (it != portMap.end()) {
      session->localPort = it->second;
    }
  }

  return session;
}

static const uint8_t charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

bool TurnThread::getTurnCandidate(const std::shared_ptr<IceSession>& turnSession)
{
  uint8_t transaction_id[OV_STUN_TRANSACTION_ID_LENGTH];
  {
    std::unique_lock<std::mutex> lock(mutex);

    if (turnSession->localPort.get() == nullptr)
      return false;

    for (int index = 0; index < OV_STUN_TRANSACTION_ID_LENGTH; index++)
  	{
  		transaction_id[index] = charset[rand() % OV_COUNTOF(charset)];
  	}
    //turnSession->timeout = std::chrono::steady_clock::now() + std::chrono::seconds(5);

    std::string transactionStr;
    transactionStr.assign((const char *)(&transaction_id[0]), OV_STUN_TRANSACTION_ID_LENGTH);

    iceTransactions.insert(std::make_pair(transactionStr, turnSession));

    for (auto it = iceTransactions.begin(); it != iceTransactions.end(); ++it) {
      printf("STORED ICE TXN %s\n", it->first.c_str());
    }

    addTimeout(transactionStr, 2);
    turnSession->state = TurnThread::IceSession::STATE_BINDING;
  }

  StunMessage message;

  message.SetClass(StunClass::Request);
  message.SetMethod(StunMethod::Binding);

  message.SetTransactionId(&(transaction_id[0]));

  auto send_data = message.Serialize();

  auto sock = turnSession->localPort->GetSocket();
  sock->SendTo(turnSession->turnAddress, send_data);
  {
    std::unique_lock<std::mutex> lock(mutex);
    turnSession->cond.wait_for(lock, std::chrono::seconds(5));
  }

  ov::SocketAddress relayedAddress = turnSession->GetRelayedAddress();
  if (relayedAddress.IsValid())
    return true;

  return false;
}

bool TurnThread::onStunBinding(const StunMessage& msg)
{
  std::shared_ptr<IceSession> session;
  {
    std::unique_lock<std::mutex> lock(mutex);
    const uint8_t* transaction_id = msg.GetTransactionId();
    if (transaction_id == nullptr) {
      return false;
    }
    std::string transactionStr;
    transactionStr.assign((const char *)transaction_id, OV_STUN_TRANSACTION_ID_LENGTH);

    printf("INCOMING ICE TXN %s\n", transactionStr.c_str());
    for (auto it = iceTransactions.begin(); it != iceTransactions.end(); ++it) {
      printf("STORED ICE TXN %s\n", it->first.c_str());
    }

    auto it = iceTransactions.find(transactionStr);
    if (it == iceTransactions.end()) {
      return false;
    }
    session = it->second;
    iceTransactions.erase(it);
  }

  if (session->state != IceSession::STATE_BINDING)
    return false;

  auto xor_addr_attribute = msg.GetAttribute<StunXorMappedAddressAttribute>(StunAttributeType::XorMappedAddress);
  if (xor_addr_attribute == nullptr)
    return false;

  session->publicAddr = xor_addr_attribute->GetAddress();


  sendInitialAllocate(session);

  return true;
}

bool TurnThread::onTurnAllocateError(const StunMessage& msg)
{
  std::shared_ptr<IceSession> session;
  {
    std::unique_lock<std::mutex> lock(mutex);
    const uint8_t* transaction_id = msg.GetTransactionId();
    if (transaction_id == nullptr) {
      return false;
    }
    std::string transactionStr;
    transactionStr.assign((const char *)transaction_id, OV_STUN_TRANSACTION_ID_LENGTH);

    printf("INCOMING ICE TXN %s\n", transactionStr.c_str());
    for (auto it = iceTransactions.begin(); it != iceTransactions.end(); ++it) {
      printf("STORED ICE TXN %s\n", it->first.c_str());
    }

    auto it = iceTransactions.find(transactionStr);
    if (it == iceTransactions.end()) {
      return false;
    }
    session = it->second;
    iceTransactions.erase(it);
  }

  if (session->state != IceSession::STATE_CHALLENGING)
    return false;

  auto error_code_attr = msg.GetAttribute<StunErrorCodeAttribute>(StunAttributeType::ErrorCode);
  if (error_code_attr == nullptr)
    return false;

  printf("STUN error code %s\n", StunAttribute::StringFromErrorCode(error_code_attr->GetErrorCode()));

  if (error_code_attr->GetErrorCode() != StunErrorCode::Unauthonticated)
    return false;

  auto nonce_attribute = msg.GetAttribute<StunNonceAttribute>(StunAttributeType::Nonce);
  if (nonce_attribute == nullptr) {
    return false;
  }

  printf("NONCE: %s\n", nonce_attribute->GetValue().CStr());

  if (nonce_attribute->GetValue().GetLength() == 0) {
    return false;
  }
  session->nonce = nonce_attribute->GetValue().CStr();

  auto realm_attribute = msg.GetAttribute<StunRealmAttribute>(StunAttributeType::Realm);

  printf("REALM: %s\n", realm_attribute->GetValue().CStr());
  if (realm_attribute->GetValue().GetLength() == 0) {
    return false;
  }

  session->realm = realm_attribute->GetValue().CStr();

  sendAuthAllocate(session);

  return true;
}

bool TurnThread::onTurnAllocateSuccess(const StunMessage& msg)
{
  std::shared_ptr<IceSession> session;
  {
    std::unique_lock<std::mutex> lock(mutex);
    const uint8_t* transaction_id = msg.GetTransactionId();
    if (transaction_id == nullptr) {
      return false;
    }
    std::string transactionStr;
    transactionStr.assign((const char *)transaction_id, OV_STUN_TRANSACTION_ID_LENGTH);

    printf("INCOMING ICE TXN %s\n", transactionStr.c_str());
    for (auto it = iceTransactions.begin(); it != iceTransactions.end(); ++it) {
      printf("STORED ICE TXN %s\n", it->first.c_str());
    }

    auto it = iceTransactions.find(transactionStr);
    if (it == iceTransactions.end()) {
      return false;
    }
    session = it->second;


    if (session->state != IceSession::STATE_ALLOCATING)
      return false;

    auto lifetime_attribute = msg.GetAttribute<StunLifetimeAttribute>(StunAttributeType::Lifetime);
    if (lifetime_attribute != nullptr) {
      addLifetime(session, lifetime_attribute->GetValue());
    } else {
      iceTransactions.erase(it);
      return false;
    }
  }

  auto relayed_attribute = msg.GetAttribute<StunXorRelayedAddressAttribute>(StunAttributeType::XorRelayedAddress);
  if (relayed_attribute == nullptr)
    return false;

  session->relayedAddr = relayed_attribute->GetAddress();
  printf("RELAY ADDRESS %s\n", session->relayedAddr.ToString().CStr());

  {
    std::unique_lock<std::mutex> lock(mutex);
    session->state = IceSession::STATE_ALLOCATED;
    session->cond.notify_all();
  }

  return true;
}

void TurnThread::sendInitialAllocate(const std::shared_ptr<IceSession>& session)
{

  uint8_t transaction_id[OV_STUN_TRANSACTION_ID_LENGTH];

  for (int index = 0; index < OV_STUN_TRANSACTION_ID_LENGTH; index++)
  {
    transaction_id[index] = charset[rand() % OV_COUNTOF(charset)];
  }

  std::string transactionStr;
  transactionStr.assign((const char *)transaction_id, OV_STUN_TRANSACTION_ID_LENGTH);

  {
      std::unique_lock<std::mutex> lock(mutex);
      iceTransactions.insert(std::make_pair(transactionStr, session));
      addTimeout(transactionStr, 2);
      session->state = TurnThread::IceSession::STATE_CHALLENGING;
  }
  StunMessage message;

  message.SetClass(StunClass::Request);
  message.SetMethod(StunMethod::Allocate);

  message.SetTransactionId(&(transaction_id[0]));

  auto transportAttribute = std::make_shared<StunRequestedTransportAttribute>();
  transportAttribute->SetProtocolNumber(0x11); //UDP

  message.AddAttribute(std::move(transportAttribute));

  auto send_data = message.Serialize();
  auto sock = session->localPort->GetSocket();
  sock->SendTo(session->turnAddress, send_data);

}

void TurnThread::sendAuthAllocate(const std::shared_ptr<IceSession>& session)
{

  uint8_t transaction_id[OV_STUN_TRANSACTION_ID_LENGTH];

  for (int index = 0; index < OV_STUN_TRANSACTION_ID_LENGTH; index++)
  {
    transaction_id[index] = charset[rand() % OV_COUNTOF(charset)];
  }

  std::string transactionStr;
  transactionStr.assign((const char *)transaction_id, OV_STUN_TRANSACTION_ID_LENGTH);

  {
      std::unique_lock<std::mutex> lock(mutex);
      iceTransactions.insert(std::make_pair(transactionStr, session));
      addTimeout(transactionStr, 2);
      session->state = TurnThread::IceSession::STATE_ALLOCATING;
  }
  StunMessage message;

  message.SetClass(StunClass::Request);
  message.SetMethod(StunMethod::Allocate);

  message.SetTransactionId(&(transaction_id[0]));

  auto transportAttribute = std::make_shared<StunRequestedTransportAttribute>();
  transportAttribute->SetProtocolNumber(0x11); //UDP

  message.AddAttribute(std::move(transportAttribute));

  auto nonce_attribute = std::make_shared<StunNonceAttribute>();
  nonce_attribute->SetText(ov::String(session->nonce.c_str()));

  message.AddAttribute(std::move(nonce_attribute));

  auto realm_attribute = std::make_shared<StunRealmAttribute>();
  realm_attribute->SetText(ov::String(session->realm.c_str()));

  message.AddAttribute(std::move(realm_attribute));

  auto user_name_attribute = std::make_shared<StunUserNameAttribute>();
  user_name_attribute->SetText(ov::String(session->user.c_str()));

  message.AddAttribute(std::move(user_name_attribute));

  auto lifetime_attribute = std::make_shared<StunLifetimeAttribute>();
  lifetime_attribute->SetValue(900);

  message.AddAttribute(std::move(lifetime_attribute));

  auto hmac_key = ov::MessageDigest::ComputeDigest(ov::CryptoAlgorithm::Md5,
		ov::String::FormatString("%s:%s:%s", session->user.c_str(),
    session->realm.c_str(), session->password.c_str()).ToData(false))->ToString();

  auto send_data = message.Serialize(hmac_key);
  auto sock = session->localPort->GetSocket();
  sock->SendTo(session->turnAddress, send_data);
}

void TurnThread::addTimeout(const std::string& transaction, unsigned seconds)
{
  auto timeout = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
  if (iceTimeouts.empty() || iceTimeouts.begin()->first > timeout) {
    cond.notify_one();
  }
  iceTimeouts.insert(std::make_pair(timeout, transaction));
}

void TurnThread::addLifetime(const std::shared_ptr<IceSession>& session, unsigned seconds)
{
  auto lifetime = std::chrono::steady_clock::now() + std::chrono::seconds(seconds) - std::chrono::seconds(5);
  if (iceLifetimes.empty() || iceLifetimes.begin()->first > lifetime) {
    cond.notify_one();
  }
  iceLifetimes.insert(std::make_pair(lifetime, session));
}

void TurnThread::run()
{

}

bool TurnThread::setTurnPermission(const std::shared_ptr<IceSession>& session, const ov::SocketAddress& remoteCandidate)
{
  ov::SocketAddress theRemote = remoteCandidate;

  if (remoteCandidate.GetFamily() == ov::SocketFamily::Inet6) {
    const sockaddr_in6 * tmpAddr = remoteCandidate.AddressForIPv6();
    const char* tmpBytes = (const char*) tmpAddr;
    tmpBytes += 12;
    struct in_addr v4Addr = { *(const in_addr_t *)tmpBytes };
    struct sockaddr_in v4InAddr = {AF_INET, tmpAddr->sin6_port, v4Addr};
    theRemote = ov::SocketAddress(v4InAddr);
  }


  {
    std::unique_lock<std::mutex> lock(mutex);
    if (session->state != IceSession::STATE_ALLOCATED)
      return false;

    IceSession::Peer peer;
    peer.remoteCandidate = theRemote;
    peer.state = IceSession::Peer::PEER_REQUESTING_PERMISSION;
  }

  uint8_t transaction_id[OV_STUN_TRANSACTION_ID_LENGTH];

  for (int index = 0; index < OV_STUN_TRANSACTION_ID_LENGTH; index++)
  {
    transaction_id[index] = charset[rand() % OV_COUNTOF(charset)];
  }

  std::string transactionStr;
  transactionStr.assign((const char *)transaction_id, OV_STUN_TRANSACTION_ID_LENGTH);

  {
      std::unique_lock<std::mutex> lock(mutex);
      iceTransactions.insert(std::make_pair(transactionStr, session));
      addTimeout(transactionStr, 2);
  }
  StunMessage message;

  message.SetClass(StunClass::Request);
  message.SetMethod(StunMethod::CreatePermission);

  message.SetTransactionId(&(transaction_id[0]));

  auto xor_peer_attribute = std::make_shared<StunXorPeerAddressAttribute>();
  xor_peer_attribute->SetParameters(theRemote);

  message.AddAttribute(std::move(xor_peer_attribute));

  auto hmac_key = ov::MessageDigest::ComputeDigest(ov::CryptoAlgorithm::Md5,
		ov::String::FormatString("%s:%s:%s", session->user.c_str(),
    session->realm.c_str(), session->password.c_str()).ToData(false))->ToString();


  auto send_data = message.Serialize(hmac_key);
  auto sock = session->localPort->GetSocket();
  sock->SendTo(session->turnAddress, send_data);

  return true;
}
