#include "chatroom-info.hpp"
#include <boost/test/unit_test.hpp>
#include <ndn-cxx/encoding/block.hpp>

namespace chronochat {

namespace tests {

using std::string;

BOOST_AUTO_TEST_SUITE(TestChatroomInfo)

const uint8_t chatroomInfo[] = {
  0x80, 0x5d, // ChatroomInfo
    0x81, 0x06, // ChatroomName
      0x08, 0x04,
        0x06e, 0x64, 0x6e, 0x64,
    0x82, 0x01, // TrustModel
      0x01,
    0x83, 0x12, // ChatroomPrefix
      0x07, 0x10,
        0x08, 0x03,
          0x6e, 0x64, 0x6e,
        0x08, 0x09,
          0x62, 0x72, 0x6f, 0x61, 0x64, 0x63, 0x61, 0x73, 0x74,
    0x84, 0x14, // ManagerPrefix
      0x07, 0x12,
        0x08, 0x03,
          0x6e, 0x64, 0x6e,
        0x08, 0x04,
          0x75, 0x63, 0x6c, 0x61,
        0x08, 0x05,
          0x61, 0x6c, 0x69, 0x63, 0x65,
    0x85, 0x26,// Participants
      0x07, 0x12,
        0x08, 0x03,
          0x6e, 0x64, 0x6e,
        0x08, 0x04,
          0x75, 0x63, 0x6c, 0x61,
        0x08, 0x05,
          0x61, 0x6c, 0x69, 0x63, 0x65,
      0x07, 0x10,
        0x08, 0x03,
          0x6e, 0x64, 0x6e,
        0x08, 0x04,
          0x75, 0x63, 0x6c, 0x61,
        0x08, 0x03,
          0x79, 0x6d, 0x6a
};

BOOST_AUTO_TEST_CASE(EncodeChatroom)
{

  // ChatroomInfo := CHATROOM-INFO-TYPE TLV-LENGTH
  //                   ChatroomName
  //                   TrustModel
  //                   ChatroomPrefix
  //                   ManagerPrefix
  //                   Participants
  //
  // ChatroomName := CHATROOM-NAME-TYPE TLV-LENGTH
  //                   NameComponent
  //
  // TrustModel := TRUST-MODEL-TYPE TLV-LENGTH
  //                 nonNegativeInteger
  //
  // ChatroomPrefix := CHATROOM-PREFIX-TYPE TLV-LENGTH
  //                     Name
  //
  // ManagerPrefix := MANAGER-PREFIX-TYPE TLV-LENGTH
  //                    Name
  //
  // Participants := PARTICIPANTS-TYPE TLV-LENGTH
  //                   Name+

  ChatroomInfo chatroom;
  chatroom.setName(ndn::Name::Component("ndnd"));
  chatroom.setManager("/ndn/ucla/alice");
  chatroom.setSyncPrefix("/ndn/broadcast");
  chatroom.addParticipant(Name("/ndn/ucla/alice"));
  chatroom.addParticipant(Name("/ndn/ucla/ymj"));
  chatroom.addParticipant(Name("/ndn/ucla"));
  chatroom.removeParticipant(Name("/ndn/ucla"));
  chatroom.setTrustModel(ChatroomInfo::TRUST_MODEL_WEBOFTRUST);

  const Block& encoded = chatroom.wireEncode();

  Block chatroomInfoBlock(chatroomInfo, sizeof(chatroomInfo));

  BOOST_CHECK_EQUAL_COLLECTIONS(chatroomInfoBlock.wire(),
                                chatroomInfoBlock.wire() + chatroomInfoBlock.size(),
                                encoded.wire(),
                                encoded.wire() + encoded.size());
}

BOOST_AUTO_TEST_CASE(DecodeChatroomCorrect)
{
  ChatroomInfo chatroom;
  chatroom.setName(ndn::Name::Component("ndnd"));
  chatroom.setManager("/ndn/ucla/alice");
  chatroom.setSyncPrefix("/ndn/broadcast");
  chatroom.addParticipant(Name("/ndn/ucla/alice"));
  chatroom.addParticipant(Name("/ndn/ucla/ymj"));
  chatroom.setTrustModel(ChatroomInfo::TRUST_MODEL_WEBOFTRUST);

  Block chatroomInfoBlock(chatroomInfo, sizeof(chatroomInfo));
  ChatroomInfo dechatroom;
  dechatroom.wireDecode(chatroomInfoBlock);

  BOOST_CHECK_EQUAL(chatroom.getName(), dechatroom.getName());
  BOOST_CHECK_EQUAL(chatroom.getSyncPrefix().toUri(), dechatroom.getSyncPrefix().toUri());
  BOOST_CHECK_EQUAL(chatroom.getManagerPrefix().toUri(), dechatroom.getManagerPrefix().toUri());
  BOOST_CHECK_EQUAL(chatroom.getParticipants().size(), dechatroom.getParticipants().size());
  BOOST_CHECK_EQUAL(chatroom.getParticipants().begin()->toUri(),
                    dechatroom.getParticipants().begin()->toUri());
  BOOST_CHECK_EQUAL(chatroom.getParticipants().begin()->toUri(),
                    dechatroom.getParticipants().begin()->toUri());
}

BOOST_AUTO_TEST_CASE(DecodeChatroomError)
{
  const uint8_t error1[] = {
    0x81, 0x5d, // ChatroomInfo Type Error
      0x81, 0x06, // ChatroomName
        0x08, 0x04,
          0x06e, 0x64, 0x6e, 0x64,
      0x82, 0x01, // TrustModel
        0x01,
      0x83, 0x12, // ChatroomPrefix
        0x07, 0x10,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x09,
            0x62, 0x72, 0x6f, 0x61, 0x64, 0x63, 0x61, 0x73, 0x74,
      0x84, 0x14, // ManagerPrefix
        0x07, 0x12,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x04,
            0x75, 0x63, 0x6c, 0x61,
          0x08, 0x05,
            0x61, 0x6c, 0x69, 0x63, 0x65,
      0x85, 0x26,// Participants
        0x07, 0x12,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x04,
            0x75, 0x63, 0x6c, 0x61,
          0x08, 0x05,
            0x61, 0x6c, 0x69, 0x63, 0x65,
        0x07, 0x10,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x04,
            0x75, 0x63, 0x6c, 0x61,
          0x08, 0x03,
            0x79, 0x6d, 0x6a
  };

  Block errorBlock1(error1, sizeof(error1));
  BOOST_CHECK_THROW(ChatroomInfo chatroom(errorBlock1), ChatroomInfo::Error);

  const uint8_t error2[] = {
    0x80, 0x5d, // ChatroomInfo
      0x81, 0x06, // ChatroomName
        0x08, 0x04,
          0x06e, 0x64, 0x6e, 0x64,
      0x83, 0x01, // TrustModel Type Error
        0x01,
      0x83, 0x12, // ChatroomPrefix
        0x07, 0x10,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x09,
            0x62, 0x72, 0x6f, 0x61, 0x64, 0x63, 0x61, 0x73, 0x74,
      0x84, 0x14, // ManagerPrefix
        0x07, 0x12,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x04,
            0x75, 0x63, 0x6c, 0x61,
          0x08, 0x05,
            0x61, 0x6c, 0x69, 0x63, 0x65,
      0x85, 0x26,// Participants
        0x07, 0x12,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x04,
            0x75, 0x63, 0x6c, 0x61,
          0x08, 0x05,
            0x61, 0x6c, 0x69, 0x63, 0x65,
        0x07, 0x10,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x04,
            0x75, 0x63, 0x6c, 0x61,
          0x08, 0x03,
            0x79, 0x6d, 0x6a
  };

  Block errorBlock2(error2, sizeof(error2));
  BOOST_CHECK_THROW(ChatroomInfo chatroom(errorBlock2), ChatroomInfo::Error);

  const uint8_t error3[] = {
    0x80, 0x5d, // ChatroomInfo
      0x81, 0x06, // ChatroomName
        0x08, 0x04,
          0x06e, 0x64, 0x6e, 0x64,
      0x82, 0x01, // TrustModel
        0x01,
      0x80, 0x12, // ChatroomPrefix Type Error
        0x07, 0x10,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x09,
            0x62, 0x72, 0x6f, 0x61, 0x64, 0x63, 0x61, 0x73, 0x74,
      0x84, 0x14, // ManagerPrefix
        0x07, 0x12,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x04,
            0x75, 0x63, 0x6c, 0x61,
          0x08, 0x05,
            0x61, 0x6c, 0x69, 0x63, 0x65,
      0x85, 0x26,// Participants
        0x07, 0x12,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x04,
            0x75, 0x63, 0x6c, 0x61,
          0x08, 0x05,
            0x61, 0x6c, 0x69, 0x63, 0x65,
        0x07, 0x10,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x04,
            0x75, 0x63, 0x6c, 0x61,
          0x08, 0x03,
            0x79, 0x6d, 0x6a
  };

  Block errorBlock3(error3, sizeof(error3));
  BOOST_CHECK_THROW(ChatroomInfo chatroom(errorBlock3), ChatroomInfo::Error);

  const uint8_t error4[] = {
    0x80, 0x5d, // ChatroomInfo
      0x81, 0x06, // ChatroomName
        0x08, 0x04,
          0x06e, 0x64, 0x6e, 0x64,
      0x82, 0x01, // TrustModel
        0x01,
      0x83, 0x12, // ChatroomPrefix
        0x07, 0x10,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x09,
            0x62, 0x72, 0x6f, 0x61, 0x64, 0x63, 0x61, 0x73, 0x74,
      0x80, 0x14, // ManagerPrefix Error Type
        0x07, 0x12,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x04,
            0x75, 0x63, 0x6c, 0x61,
          0x08, 0x05,
            0x61, 0x6c, 0x69, 0x63, 0x65,
      0x85, 0x26,// Participants
        0x07, 0x12,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x04,
            0x75, 0x63, 0x6c, 0x61,
          0x08, 0x05,
            0x61, 0x6c, 0x69, 0x63, 0x65,
        0x07, 0x10,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x04,
            0x75, 0x63, 0x6c, 0x61,
          0x08, 0x03,
            0x79, 0x6d, 0x6a
  };

  Block errorBlock4(error4, sizeof(error4));
  BOOST_CHECK_THROW(ChatroomInfo chatroom(errorBlock4), ChatroomInfo::Error);

  const uint8_t error5[] = {
    0x80, 0x5d, // ChatroomInfo
      0x81, 0x06, // ChatroomName
        0x08, 0x04,
          0x06e, 0x64, 0x6e, 0x64,
      0x82, 0x01, // TrustModel
        0x01,
      0x83, 0x12, // ChatroomPrefix
        0x07, 0x10,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x09,
            0x62, 0x72, 0x6f, 0x61, 0x64, 0x63, 0x61, 0x73, 0x74,
      0x84, 0x14, // ManagerPrefix
        0x07, 0x12,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x04,
            0x75, 0x63, 0x6c, 0x61,
          0x08, 0x05,
            0x61, 0x6c, 0x69, 0x63, 0x65,
      0x80, 0x26,// Participants Error Type
        0x07, 0x12,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x04,
            0x75, 0x63, 0x6c, 0x61,
          0x08, 0x05,
            0x61, 0x6c, 0x69, 0x63, 0x65,
        0x07, 0x10,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x04,
            0x75, 0x63, 0x6c, 0x61,
          0x08, 0x03,
            0x79, 0x6d, 0x6a
  };

  Block errorBlock5(error5, sizeof(error5));
  BOOST_CHECK_THROW(ChatroomInfo chatroom(errorBlock5), ChatroomInfo::Error);

  const uint8_t error6[] = {
    0x80, 0x00 // Empty ChatroomInfo
  };

  Block errorBlock6(error6, sizeof(error6));
  BOOST_CHECK_THROW(ChatroomInfo chatroom(errorBlock6), ChatroomInfo::Error);

  const uint8_t error7[] = {
    0x80, 0x1f, // ChatroomInfo
      0x81, 0x06, // ChatroomName
        0x08, 0x04,
          0x06e, 0x64, 0x6e, 0x64,
      0x82, 0x01, // TrustModel
        0x01,
      0x83, 0x12, // ChatroomPrefix
        0x07, 0x10,
          0x08, 0x03,
            0x6e, 0x64, 0x6e,
          0x08, 0x09,
            0x62, 0x72, 0x6f, 0x61, 0x64, 0x63, 0x61, 0x73, 0x74,
    // no Participant
  };

  Block errorBlock7(error7, sizeof(error7));
  BOOST_CHECK_THROW(ChatroomInfo chatroom(errorBlock7), ChatroomInfo::Error);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests

} // namespace chronochat