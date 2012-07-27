package play.api.libs.openid

import play.api.libs.ws.WS.WSRequestHolder
import play.api.libs.concurrent.{Thrown, Redeemed, Promise}
import play.api.libs.openid.Errors.NO_SERVER

trait Normalization {
  def normalizeIdentifier(openID: String) = new UrlIdentifier(openID.trim).normalize
}

trait WSEnabled {
  def ws: String => WSRequestHolder
}

trait Discovery { self: WSEnabled with Normalization =>
  /**
   * Resolve the OpenID server from the user's OpenID
   */
  def discoverServer(openID: String): Promise[OpenIDServer]

  /**
   * Resolve the OpenID server from the user's claimed ID (which might not support discovery)
   */
  def discoverServerViaUserId(claimedId: String): Promise[OpenIDServer]
}

trait BaseDiscovery extends Discovery { self: WSEnabled with Normalization =>

  def discoverServer(openID: String): Promise[OpenIDServer] = {
    normalizeIdentifier(openID) map {
      discoveryUrl =>
        ws(discoveryUrl).get().map(response => {
          val maybeResponse = if (response.status == 200) {
            new XrdsResolver().resolve(response) orElse new HtmlResolver().resolve(response)
          } else { None }
          maybeResponse.getOrElse(throw Errors.NETWORK_ERROR)
        })
    } getOrElse Promise.pure(throw Errors.MISSING_PARAMETERS)
  }

  def discoverServerViaUserId(claimedId: String): Promise[OpenIDServer] = discoverServer(claimedId)
}

/**
 * Resolve the OpenID identifier making use of the fact that this is using Google as an OpenID provider.
 */
class GoogleOpenIdDiscovery(val ws: String => WSRequestHolder) extends BaseDiscovery with WSEnabled with Normalization {
  /**
   * Resolve the OpenID endpoint based on the claimed ID Google returned
   *
   * See https://sites.google.com/site/oauthgoog/fedlogininterp/openiddiscovery
   */
  override def discoverServerViaUserId(claimedId: String): Promise[OpenIDServer] = {
    val userDiscoveryUrl = "https://www.google.com/accounts/o8/user-xrds?uri=%s" format java.net.URLEncoder.encode(claimedId, "UTF-8")
    ws(userDiscoveryUrl).get().map(response => {
      val maybeResponse = if (response.status == 200) { new XrdsResolver().resolve(response) } else { None }
      maybeResponse.getOrElse(throw Errors.NETWORK_ERROR)
    })
  }
}

/**
 * Resolve the OpenID identifier to the location of the user's OpenID service provider.
 *
 * Known limitations:
 *
 * * The Discovery doesn't support XRIs at the moment
 */
class DefaultDiscovery(val ws: String => WSRequestHolder) extends BaseDiscovery with WSEnabled with Normalization

/**
 * Treat a list of `Discovery` instances as a single instance. Can be used to provide a fallback mechanism if discovery fails.
 */
class CompositeDiscovery(val ws: String => WSRequestHolder, discoveryList: Seq[Discovery]) extends Discovery with WSEnabled with Normalization {

  def discoverServer(openID: String) = run(discoveryList, NO_SERVER) { _.discoverServer(openID) }

  def discoverServerViaUserId(claimedId: String) = run(discoveryList, NO_SERVER) { _.discoverServerViaUserId(claimedId) }

  private def run[A, B](l: Seq[B], onError: Throwable)(f: B => Promise[A]): Promise[A] = l match {
    case h :: tail => f(h).extend(_.value match {
      case Thrown(e) => run(tail, onError)(f)
      case Redeemed(server)  => Promise.pure(server)
    }).flatMap { identity }
    case Nil => Promise.pure(throw onError)
  }
}