package play.api.libs.openid

import scala.util.control.Exception._
import play.api.libs.concurrent.Promise
import scala.util.matching.Regex
import play.api.http.HeaderNames
import play.api.libs.concurrent.PurePromise
import play.api.libs.ws.WS.WSRequestHolder
import java.net._
import play.api.mvc.Request
import play.api.libs.ws._
import xml.Node

import play.api.libs.concurrent.execution.defaultContext

case class OpenIDServer(url: String, delegate: Option[String])

case class UserInfo(id: String, attributes: Map[String, String] = Map.empty)

/**
 * provides user information for a verified user
 */
object UserInfo {

  def apply(queryString: Map[String, Seq[String]]): UserInfo = {
    val extractor = new UserInfoExtractor(queryString)
    val id = extractor.id getOrElse(throw Errors.BAD_RESPONSE)
    new UserInfo(id, extractor.axAttributes)
  }

  /** Extract the values required to create an instance of the UserInfo
   *
   * The UserInfoExtractor ensures that attributes returned via OpenId attribute exchange are signed
   * (i.e. listed in the openid.signed field) and verified in the check_authentication step.
   */
  private[openid] class UserInfoExtractor(params:Map[String, Seq[String]]) {
    val AxAttribute =  """^openid\.([^.]+\.value\.([^.]+(\.\d+)?))$""".r
    val extractAxAttribute: PartialFunction[String, (String,String)] = {
      case AxAttribute(fullKey, key, num) => (fullKey, key) // fullKey e.g. 'ext1.value.email', shortKey e.g. 'email' or 'fav_movie.2'
    }

    private lazy val signedFields = params.get("openid.signed") flatMap {_.headOption map {_.split(",")}} getOrElse(Array())

    def id = params.get("openid.claimed_id").flatMap(_.headOption).orElse(params.get("openid.identity").flatMap(_.headOption))

    def axAttributes = params.foldLeft(Map[String,String]()) {
      case (result, (key, values)) => extractAxAttribute.lift(key) flatMap {
        case (fullKey, shortKey) if signedFields.contains(fullKey) => values.headOption map {value => Map(shortKey -> value)}
        case _ => None
      } map(result ++ _) getOrElse result
    }
  }

}

/**
 * provides OpenID support
 */
object OpenID extends OpenIDClient(WS.url)

private[openid] class OpenIDClient(ws: (String) => WSRequestHolder) {

  val discovery = new Discovery(ws)

  /**
   * Retrieve the URL where the user should be redirected to start the OpenID authentication process
   */
  def redirectURL(openID: String,
    callbackURL: String,
    axRequired: Seq[(String, String)] = Seq.empty,
    axOptional: Seq[(String, String)] = Seq.empty,
    realm: Option[String] = None): Promise[String] = {

    val claimedId = discovery.normalizeIdentifier(openID)
    discovery.discoverServer(openID).map({server =>
      val parameters = Seq(
        "openid.ns" -> "http://specs.openid.net/auth/2.0",
        "openid.mode" -> "checkid_setup",
        "openid.claimed_id" -> claimedId,
        "openid.identity" -> server.delegate.getOrElse(claimedId),
        "openid.return_to" -> callbackURL
      ) ++ axParameters(axRequired, axOptional) ++ realm.map("openid.realm" -> _).toList
      val separator = if (server.url.contains("?")) "&" else "?"
      server.url + separator + parameters.map(pair => pair._1 + "=" + URLEncoder.encode(pair._2, "UTF-8")).mkString("&")
    })
  }

  /**
   * From a request corresponding to the callback from the OpenID server, check the identity of the current user
   */
  def verifiedId(implicit request: Request[_]): Promise[UserInfo] = verifiedId(request.queryString)

  /**
   * For internal use
   */
  def verifiedId(queryString: java.util.Map[String, Array[String]]): Promise[UserInfo] = {
    import scala.collection.JavaConversions._
    verifiedId(queryString.toMap.mapValues(_.toSeq))
  }

  private def verifiedId(queryString: Map[String, Seq[String]]): Promise[UserInfo] = {
    (queryString.get("openid.mode").flatMap(_.headOption),
      queryString.get("openid.claimed_id").flatMap(_.headOption).orElse(queryString.get("openid.identity").flatMap(_.headOption)),
      queryString.get("openid.op_endpoint").flatMap(_.headOption)) match {
      case (Some("id_res"), Some(id), endPoint) => {
        val server: Promise[String] = endPoint.map(PurePromise(_)).getOrElse(discovery.discoverServer(id).map(_.url))
        server.flatMap(url => {
          val fields = (queryString - "openid.mode" + ("openid.mode" -> Seq("check_authentication")))
          ws(url).post(fields).map(response => {
            if (response.status == 200 && response.body.contains("is_valid:true")) {
              UserInfo(queryString)
            } else throw Errors.AUTH_ERROR
          })
        })
      }
      case _ => PurePromise(throw Errors.BAD_RESPONSE)
    }
  }

  private def axParameters(axRequired: Seq[(String, String)],
                           axOptional: Seq[(String, String)]): Seq[(String, String)] = {
    if (axRequired.length == 0 && axOptional.length == 0)
      Nil
    else {
      val axRequiredParams = if (axRequired.size == 0) Nil
      else Seq("openid.ax.required" -> axRequired.map(_._1).mkString(","))

      val axOptionalParams = if (axOptional.size == 0) Nil
      else Seq("openid.ax.if_available" -> axOptional.map(_._1).mkString(","))

      val definitions = (axRequired ++ axOptional).map(attribute => ("openid.ax.type." + attribute._1 -> attribute._2))

      Seq("openid.ns.ax" -> "http://openid.net/srv/ax/1.0", "openid.ax.mode" -> "fetch_request") ++ axRequiredParams ++ axOptionalParams ++ definitions
    }
  }
}

/**
 *  Resolve the OpenID identifier to the location of the user's OpenID service provider.
 *
 *  Known limitations:
 *
 *   * The Discovery doesn't support XRIs at the moment
 */
private[openid] class Discovery(ws: (String) => WSRequestHolder) {

  case class UrlIdentifier(url: String) {
    def normalize = catching(classOf[MalformedURLException], classOf[URISyntaxException]) opt {
      def port(p:Int) = p match {
        case 80 | 443 => -1
        case port => port
      }
      def schemeForPort(p: Int) = p match {
        case 443 => "https"
       case _ => "http"
      }
      def scheme(uri:URI) = Option(uri.getScheme) getOrElse schemeForPort(uri.getPort)
      def path(path:String) = if(null == path || path.isEmpty) "/" else path

      val uri = (if(url.matches("^(http|HTTP)(s|S)?:.*")) new URI(url) else new URI("http://" + url)).normalize()
      new URI(scheme(uri), uri.getUserInfo, uri.getHost.toLowerCase, port(uri.getPort), path(uri.getPath), uri.getQuery, null).toURL.toExternalForm
    }
  }

  trait Resolver {
    def resolve(response:Response):Option[OpenIDServer]
  }

  class XrdsResolver extends Resolver {
    // http://openid.net/specs/openid-authentication-2_0.html#service_elements
    private val serviceTypeId = Seq("http://specs.openid.net/auth/2.0/server", "http://specs.openid.net/auth/2.0/signon")

    def resolve(response: Response) = for {
      _ <- response.header(HeaderNames.CONTENT_TYPE).filter(_.contains("application/xrds+xml"))
      val findInXml = findUriWithType(response.xml) _
      uri <- serviceTypeId.flatMap(findInXml(_)).headOption
    } yield OpenIDServer(uri, None)

    private def findUriWithType(xml: Node)(typeId: String) = (xml \ "XRD" \ "Service" find (node => (node \ "Type").text == typeId)).map {
      node =>
        (node \ "URI").text.trim
    }
  }

  class HtmlResolver extends Resolver {
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

  def normalizeIdentifier(openID: String) = {
      val trimmed = openID.trim
      UrlIdentifier(trimmed).normalize getOrElse trimmed
    }

  /**
   * Resolve the OpenID server from the user's OpenID
   */
  def discoverServer(openID:String): Promise[OpenIDServer] = {
    val discoveryUrl = normalizeIdentifier(openID)
    ws(discoveryUrl).get().map(response => {
      val maybeOpenIdServer = new XrdsResolver().resolve(response) orElse new HtmlResolver().resolve(response)
      maybeOpenIdServer.getOrElse(throw Errors.NETWORK_ERROR)
    })
  }
}

