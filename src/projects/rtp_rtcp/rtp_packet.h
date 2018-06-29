#pragma once

#include <vector>
#include <memory>
#include "base/ovlibrary/data.h"

#define RTP_VERSION					2
#define FIXED_HEADER_SIZE			12
#define ONE_BYTE_EXTENSION_ID		0xBEDE
#define ONE_BYTE_HEADER_SIZE		1
#define DEFAULT_MAX_PACKET_SIZE		1500 - 28

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |V=2|P|X|  CC   |M|     PT      |       sequence number         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           timestamp                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           synchronization source (SSRC) identifier            |
// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
// |            Contributing source (CSRC) identifiers             |
// |                             ....                              |
// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
// |One-byte eXtensions id = 0xbede|       length in 32bits        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Extensions                           |
// |                             ....                              |
// +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
// |                           Payload                             |
// |             ....              :  padding...                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               padding         | Padding size  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class RtpPacket
{
public:
	RtpPacket();
	RtpPacket(RtpPacket &src);
	~RtpPacket();

	// Getter
	bool		Marker();
	uint8_t		PayloadType();
	uint16_t	SequenceNumber();
	uint32_t	Timestamp();
	uint32_t	Ssrc();
	std::vector<uint32_t> Csrcs();
	uint8_t*	Buffer();

	// Setter
	void		SetMarker(bool marker_bit);
	void		SetPayloadType(uint8_t payload_type);
	void		SetSequenceNumber(uint16_t seq_no);
	void		SetTimestamp(uint32_t timestamp);
	void		SetSsrc(uint32_t ssrc);
	
	// 버퍼에 남은 공간이 충분하고 extension, payload, padding이 
	// 들어가기 전에 호출되어야 함
	void		SetCsrcs(const std::vector<uint32_t>& csrcs);

	size_t		HeadersSize();
	size_t		PayloadSize();
	size_t		PaddingSize();

	// Payload
	uint8_t*	SetPayloadSize(size_t size_bytes);
	uint8_t*	AllocatePayload(size_t size_bytes);
	uint8_t*	payload();

	// Data
	std::shared_ptr<ov::Data> GetData();
	
private:
	bool		_marker;
	uint8_t		_payload_type;
	uint8_t		_padding_size;
	uint16_t	_sequence_number;
	uint32_t	_timestamp;
	uint32_t	_ssrc;
	size_t		_payload_offset;	// Header Start Point (Header size)
	size_t		_payload_size;		// Payload Size

	//TODO: Extension은 향후 확장
	size_t		_extension_size;

	// BYTE로 변환된 헤더
	// std::vector<uint8_t>	_buffer;
	uint8_t *					_buffer;
	std::shared_ptr<ov::Data>	_data;
};

