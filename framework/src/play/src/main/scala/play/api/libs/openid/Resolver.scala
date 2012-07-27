package play.api.libs.openid

import scala.util.matching.Regex
import play.api.http.HeaderNames
import play.api.libs.ws._
import xml.Node

trait Resolver {
  def resolve(response: Response): Option[OpenIDServer]
}

// TODO: Verify schema, namespace and support verification of XML signatures
private[openid] class XrdsResolver extends Resolver {
  // http://openid.net/specs/openid-authentication-2_0.html#service_elements and
  // OpenID 1 compatibility: http://openid.net/specs/openid-authentication-2_0.html#anchor38
  private val serviceTypeId = Seq("http://specs.openid.net/auth/2.0/server", "http://specs.openid.net/auth/2.0/signon", "http://openid.net/server/1.0", "http://openid.net/server/1.1")

  def resolve(response: Response) = for {
    _ <- response.header(HeaderNames.CONTENT_TYPE).filter(_.contains("application/xrds+xml"))
    val findInXml = findUriWithType(response.xml) _
    uri <- serviceTypeId.flatMap(findInXml(_)).headOption
  } yield OpenIDServer(uri, None)

  private def findUriWithType(xml: Node)(typeId: String) = (xml \ "XRD" \ "Service").find(service => (service \ "Type").find(ty => ty.text == typeId).isDefined).map {
    node =>
      (node \ "URI").text.trim
  }
}

private[openid] class HtmlResolver extends Resolver {
  private val providerRegex = new Regex( """<link[^>]+openid2[.]provider[^>]+>""")
  private val serverRegex = new Regex( """<link[^>]+openid[.]server[^>]+>""")
  private val localidRegex = new Regex( """<link[^>]+openid2[.]local_id[^>]+>""")
  private val delegateRegex = new Regex( """<link[^>]+openid[.]delegate[^>]+>""")

  def resolve(response: Response) = {
    val serverUrl: Option[String] = providerRegex.findFirstIn(response.body)
      .orElse(serverRegex.findFirstIn(response.body))
      .flatMap(extractHref(_))
    serverUrl.map(url => {
      val delegate: Option[String] = localidRegex.findFirstIn(response.body)
        .orElse(delegateRegex.findFirstIn(response.body)).flatMap(extractHref(_))
      OpenIDServer(url, delegate)
    })
  }

  private def extractHref(link: String): Option[String] =
    new Regex( """href="([^"]*)"""").findFirstMatchIn(link).map(_.group(1).trim).
      orElse(new Regex( """href='([^']*)'""").findFirstMatchIn(link).map(_.group(1).trim))
}