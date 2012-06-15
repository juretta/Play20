package play.api.libs.openid

import org.specs2.mutable.Specification
import scala.Predef._
import org.specs2.mock.Mockito
import play.api.libs.ws.WS.WSRequestHolder
import play.api.libs.ws.Response
import play.api.libs.concurrent.Promise
import play.api.http.Status._
import play.api.mvc.Request
import play.api.http.{ContentTypeOf, Writeable, HeaderNames}

object OpenIDSpec extends Specification with Mockito {

  val claimedId = "http://example.com/openid?id=C123"
  val identity = "http://example.com/openid?id=C123&id"
  val defaultSigned = "op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle"

  "OpenID" should {
    "initiate discovery" in {
      val ws = new WSMock
      val openId = new OpenIDClient(ws.url)
      openId.redirectURL("http://example.com", "http://foo.bar.com/openid")
      there was one(ws.request).get()
    }

    "verify the response" in {
      val ws = new WSMock

      ws.response.header(HeaderNames.CONTENT_TYPE) returns Some("text/plain")
      ws.response.body returns "is_valid:true\n" // http://openid.net/specs/openid-authentication-2_0.html#kvform

      val openId = new OpenIDClient(ws.url)

      val userInfo = openId.verifiedId(setupMockRequest).value.get
      userInfo.id must be equalTo claimedId

      there was one(ws.request).post(anyString)(any[Writeable[String]], any[ContentTypeOf[String]])
    }

    "fail response verification if direct verification fails" in {
      val ws = new WSMock

      ws.response.header(HeaderNames.CONTENT_TYPE) returns Some("text/plain")
      ws.response.body returns "is_valid:false\n"

      val openId = new OpenIDClient(ws.url)

      openId.verifiedId(setupMockRequest).value.get must throwA[OpenIDError]

      there was one(ws.request).post(anyString)(any[Writeable[String]], any[ContentTypeOf[String]])
    }
  }

  def setupMockRequest = {
    val request = mock[Request[_]]
    request.queryString returns openIdResponse
    request
  }

  def openIdResponse = createDefaultResponse(claimedId, identity, defaultSigned)

}
