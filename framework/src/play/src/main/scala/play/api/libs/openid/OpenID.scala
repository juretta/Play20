package play.api.libs.openid

import play.api.libs.concurrent.{Redeemed, Thrown, Promise, PurePromise}
import play.api.libs.ws.WS.WSRequestHolder
import java.net._
import play.api.mvc.Request
import play.api.libs.ws._
import play.api.libs.openid.Errors.NO_SERVER

import play.api.libs.concurrent.execution.defaultContext

case class OpenIDServer(url: String, delegate: Option[String])

case class UserInfo(id: String, attributes: Map[String, String] = Map.empty)

/**
 * provides user information for a verified user
 */
object UserInfo {

  def apply(queryString: Map[String, Seq[String]]): UserInfo = {
    val extractor = new UserInfoExtractor(queryString)
    val id = extractor.id getOrElse (throw Errors.BAD_RESPONSE)
    new UserInfo(id, extractor.axAttributes)
  }

  /**Extract the values required to create an instance of the UserInfo
   *
   * The UserInfoExtractor ensures that attributes returned via OpenId attribute exchange are signed
   * (i.e. listed in the openid.signed field) and verified in the check_authentication step.
   */
  private[openid] class UserInfoExtractor(params: Map[String, Seq[String]]) {
    val AxAttribute = """^openid\.([^.]+\.value\.([^.]+(\.\d+)?))$""".r
    val extractAxAttribute: PartialFunction[String, (String, String)] = {
      case AxAttribute(fullKey, key, num) => (fullKey, key) // fullKey e.g. 'ext1.value.email', shortKey e.g. 'email' or 'fav_movie.2'
    }

    private lazy val signedFields = params.get("openid.signed") flatMap { _.headOption map { _.split(",") } } getOrElse (Array())

    def id = params.get("openid.claimed_id").flatMap(_.headOption).orElse(params.get("openid.identity").flatMap(_.headOption))

    def axAttributes = params.foldLeft(Map[String, String]()) {
      case (result, (key, values)) => extractAxAttribute.lift(key) flatMap {
        case (fullKey, shortKey) if signedFields.contains(fullKey) => values.headOption map {
          value => Map(shortKey -> value)
        }
        case _ => None
      } map (result ++ _) getOrElse result
    }
  }

}

/**
 * provides OpenID support
 */
object OpenID extends OpenIDClient

class OpenIDClient(val ws: (String) => WSRequestHolder = WS.url,
                                    customDiscovery:Seq[Discovery] = Seq.empty) extends Normalization {

  lazy val discoveryList = if(customDiscovery.isEmpty) Seq(new DefaultDiscovery(ws), new GoogleOpenIdDiscovery(ws)) else customDiscovery
  lazy val discovery = new CompositeDiscovery(ws, discoveryList)

  /**
   * Retrieve the URL where the user should be redirected to start the OpenID authentication process
   */
  def redirectURL(openID: String,
                  callbackURL: String,
                  axRequired: Seq[(String, String)] = Seq.empty,
                  axOptional: Seq[(String, String)] = Seq.empty,
                  realm: Option[String] = None): Promise[String] = {

    normalizeIdentifier(openID) map { claimedId =>
      discovery.discoverServer(openID) map { server =>
        val parameters = Seq(
          "openid.ns" -> "http://specs.openid.net/auth/2.0",
          "openid.mode" -> "checkid_setup",
          "openid.claimed_id" -> claimedId,
          "openid.identity" -> server.delegate.getOrElse(claimedId),
          "openid.return_to" -> callbackURL
        ) ++ axParameters(axRequired, axOptional) ++ realm.map("openid.realm" -> _).toList ++ uiExtensions
        val separator = if (server.url.contains("?")) "&" else "?"
        server.url + separator + parameters.map(pair => pair._1 + "=" + URLEncoder.encode(pair._2, "UTF-8")).mkString("&")
      }
    } getOrElse Promise.pure(throw Errors.MISSING_PARAMETERS)
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
      queryString.get("openid.claimed_id").flatMap(_.headOption), // The Claimed Identifier. "openid.claimed_id" and "openid.identity" SHALL be either both present or both absent.
      queryString.get("openid.op_endpoint").flatMap(_.headOption)) match {
      case (Some("id_res"), Some(id), _) => {
        // Must perform discovery on the claimedId to resolve the op_endpoint.
        val server: Promise[OpenIDServer] = discovery.discoverServerViaUserId(id)
        server.flatMap(server => {
          val fields = (queryString - "openid.mode" + ("openid.mode" -> Seq("check_authentication")))
          ws(server.url).post(fields).map(response => {
            if (response.status == 200 && response.body.contains("is_valid:true")) {
              UserInfo(queryString)
            } else throw Errors.AUTH_ERROR
          })
        })
      }
      case _ => PurePromise(throw Errors.BAD_RESPONSE)
    }
  }

  private val uiExtensions: Seq[(String, String)] = Seq(
    "openid.ns.ext2" -> "http://specs.openid.net/extensions/ui/1.0",
    "openid.ext2.icon" -> "true"
  )

  private def axParameters(axRequired: Seq[(String, String)],
                           axOptional: Seq[(String, String)]): Seq[(String, String)] = {
    if (axRequired.isEmpty && axOptional.isEmpty)
      Nil
    else {
      val axRequiredParams = if (axRequired.isEmpty) Nil
      else Seq("openid.ax.required" -> axRequired.map(_._1).mkString(","))

      val axOptionalParams = if (axOptional.isEmpty) Nil
      else Seq("openid.ax.if_available" -> axOptional.map(_._1).mkString(","))

      val definitions = (axRequired ++ axOptional).map(attribute => ("openid.ax.type." + attribute._1 -> attribute._2))

      Seq("openid.ns.ax" -> "http://openid.net/srv/ax/1.0", "openid.ax.mode" -> "fetch_request") ++ axRequiredParams ++ axOptionalParams ++ definitions
    }
  }
}


