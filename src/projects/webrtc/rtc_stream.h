#pragma once#include <base/ovcrypto/certificate.h>#include "base/common_video.h"#include "base/publisher/stream.h"#include "base/common_types.h"#include "ice/ice_port.h"#include "sdp/session_description.h"#include "rtp_rtcp/rtp_rtcp_defines.h"#include "rtc_session.h"class RtcStream : public Stream{public:	static std::shared_ptr<RtcStream> Create(const std::shared_ptr<Application> application,											 const StreamInfo &info);	explicit RtcStream(const std::shared_ptr<Application> application,					   const StreamInfo &info);	~RtcStream() final;	// SDP를 생성하고 관리한다.	std::shared_ptr<SessionDescription> GetSessionDescription();	void            SendVideoFrame(std::shared_ptr<MediaTrack> track,								   std::unique_ptr<EncodedFrame> encoded_frame,								   std::unique_ptr<CodecSpecificInfo> codec_info,								   std::unique_ptr<FragmentationHeader> fragmentation) override ;	// SDP의 payload type과 track을 연결한다.	void 			AddRtcTrack(uint32_t payload_type, std::shared_ptr<MediaTrack> track);	std::shared_ptr<MediaTrack>	GetRtcTrack(uint32_t payload_type);	// offer SDP Session ID로 Session을 찾는다.	std::shared_ptr<RtcSession> FindRtcSessionByPeerSDPSessionID(uint32_t session_id);private:	bool Start() override ;	bool Stop() override ;	// WebRTC의 RTP 에서 사용하는 형태로 변환한다.	void MakeRtpVideoHeader(const CodecSpecificInfo* info, RTPVideoHeader *header);	std::shared_ptr<SessionDescription>		_offer_sdp;	std::shared_ptr<Certificate>			_certificate;	// 기존 Track 정보는 WEBRTC와 연결되어있지 않기 때문에 payload type과 track을 새롭게 연결한다.	std::map<uint8_t, std::shared_ptr<MediaTrack>>	_rtc_track;};