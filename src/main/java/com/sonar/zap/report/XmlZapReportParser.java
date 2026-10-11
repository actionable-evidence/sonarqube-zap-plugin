package com.sonar.zap.report;

import com.sonar.zap.report.ZapReport.Alert;
import com.sonar.zap.report.ZapReport.Instance;
import com.sonar.zap.report.ZapReport.Site;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/** Parses the ZAP XML report (root {@code OWASPZAPReport}, or the legacy {@code OWASPZaproxyReport}). */
public class XmlZapReportParser implements ZapReportParser {

  @Override
  public ZapReport parse(InputStream in) throws IOException {
    Element root;
    try {
      root = newFactory().newDocumentBuilder().parse(in).getDocumentElement();
    } catch (ParserConfigurationException | SAXException e) {
      throw new IOException("Invalid ZAP XML report: " + e.getMessage(), e);
    }
    if (!root.getTagName().toLowerCase().startsWith("owaspzap")) {
      throw new IOException("Not a ZAP XML report: unexpected root element <" + root.getTagName() + ">");
    }
    List<Site> sites = new ArrayList<>();
    for (Element site : children(root, "site")) {
      List<Alert> alerts = new ArrayList<>();
      for (Element alertsEl : children(site, "alerts")) {
        for (Element item : children(alertsEl, "alertitem")) {
          alerts.add(readAlert(item));
        }
      }
      sites.add(new Site(site.getAttribute("name"), site.getAttribute("host"), alerts));
    }
    return new ZapReport(root.getAttribute("version"), root.getAttribute("generated"), sites);
  }

  private static DocumentBuilderFactory newFactory() throws ParserConfigurationException {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
    return factory;
  }

  private static Alert readAlert(Element item) {
    List<Instance> instances = new ArrayList<>();
    for (Element instancesEl : children(item, "instances")) {
      for (Element i : children(instancesEl, "instance")) {
        instances.add(new Instance(
          text(i, "uri"), text(i, "method"), text(i, "param"), text(i, "attack"), text(i, "evidence")));
      }
    }
    String name = text(item, "name");
    if (name.isBlank()) {
      name = text(item, "alert");
    }
    return new Alert(
      text(item, "pluginid"), text(item, "alertRef"), name,
      ParseUtils.toInt(text(item, "riskcode"), 0), text(item, "confidence"),
      text(item, "desc"), text(item, "solution"), text(item, "reference"), text(item, "otherinfo"),
      ParseUtils.toInt(text(item, "cweid"), -1), ParseUtils.toInt(text(item, "wascid"), -1),
      instances);
  }

  private static List<Element> children(Element parent, String tag) {
    List<Element> result = new ArrayList<>();
    NodeList nodes = parent.getChildNodes();
    for (int i = 0; i < nodes.getLength(); i++) {
      Node n = nodes.item(i);
      if (n instanceof Element e && e.getTagName().equals(tag)) {
        result.add(e);
      }
    }
    return result;
  }

  private static String text(Element parent, String tag) {
    List<Element> found = children(parent, tag);
    return found.isEmpty() ? "" : found.get(0).getTextContent().trim();
  }
}
