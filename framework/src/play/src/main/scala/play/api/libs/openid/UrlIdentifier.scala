package play.api.libs.openid

import java.net.{URI, URISyntaxException, MalformedURLException}
import util.control.Exception._

private[openid] class UrlIdentifier(url: String) {
  def normalize = catching(classOf[MalformedURLException], classOf[URISyntaxException]) opt {
    def port(p: Int) = p match {
      case 80 | 443 => -1
      case port => port
    }
    def schemeForPort(p: Int) = p match {
      case 443 => "https"
      case _ => "http"
    }
    def scheme(uri: URI) = Option(uri.getScheme) getOrElse schemeForPort(uri.getPort)
    def path(path: String) = if (null == path || path.isEmpty) "/" else path

    val uri = (if (url.matches("^(http|HTTP)(s|S)?:.*")) new URI(url) else new URI("http://" + url)).normalize()
    new URI(scheme(uri), uri.getUserInfo, uri.getHost.toLowerCase, port(uri.getPort), path(uri.getPath), uri.getQuery, null).toURL.toExternalForm
  }
}