package com.sonar.zap.scanner;

import com.sonar.zap.ZapConstants;
import com.sonar.zap.report.ZapReport.Alert;
import com.sonar.zap.report.ZapReport.Instance;
import java.util.Locale;
import org.sonar.api.batch.rule.Severity;
import org.sonar.api.issue.impact.SoftwareQuality;
import org.sonar.api.rules.CleanCodeAttribute;
import org.sonar.api.rules.RuleType;

/** Pure mapping helpers from ZAP alerts to Sonar rule/issue attributes. */
final class ZapIssueMapper {

  private ZapIssueMapper() {
  }

  static Severity severity(int riskCode) {
    return switch (riskCode) {
      case 3 -> Severity.CRITICAL;
      case 2 -> Severity.MAJOR;
      case 1 -> Severity.MINOR;
      default -> Severity.INFO;
    };
  }

  static org.sonar.api.issue.impact.Severity impact(int riskCode) {
    return switch (riskCode) {
      case 3 -> org.sonar.api.issue.impact.Severity.HIGH;
      case 2 -> org.sonar.api.issue.impact.Severity.MEDIUM;
      case 1 -> org.sonar.api.issue.impact.Severity.LOW;
      default -> org.sonar.api.issue.impact.Severity.INFO;
    };
  }

  static RuleType ruleType() {
    return RuleType.VULNERABILITY;
  }

  static CleanCodeAttribute cleanCodeAttribute() {
    return CleanCodeAttribute.TRUSTWORTHY;
  }

  static SoftwareQuality quality() {
    return SoftwareQuality.SECURITY;
  }

  static String ruleName(Alert alert) {
    return alert.name().isBlank() ? "ZAP alert " + alert.ruleId() : alert.name();
  }

  static String ruleDescription(Alert alert) {
    StringBuilder sb = new StringBuilder(stripHtml(alert.description()));
    append(sb, "Solution", alert.solution());
    append(sb, "Reference", alert.reference());
    if (alert.cweId() > 0) {
      sb.append("\n\nCWE-").append(alert.cweId());
    }
    if (alert.wascId() > 0) {
      sb.append(alert.cweId() > 0 ? ", " : "\n\n").append("WASC-").append(alert.wascId());
    }
    String text = sb.toString().trim();
    return text.isEmpty() ? ruleName(alert) : text;
  }

  /** Message of one issue, describing a single alert instance (or the alert when it has none). */
  static String message(Alert alert, Instance instance) {
    StringBuilder sb = new StringBuilder(ruleName(alert));
    if (instance != null) {
      String where = (instance.method() + " " + instance.uri()).trim();
      if (!where.isEmpty()) {
        sb.append(" - ").append(where);
      }
      if (!instance.param().isBlank()) {
        sb.append(" [param: ").append(instance.param()).append(']');
      }
      if (!instance.evidence().isBlank()) {
        sb.append(" [evidence: ").append(truncate(instance.evidence(), 200)).append(']');
      }
    }
    if (!alert.confidence().isBlank() && !alert.confidence().chars().allMatch(Character::isDigit)) {
      sb.append(" (confidence: ").append(alert.confidence().toLowerCase(Locale.ROOT)).append(')');
    }
    return sb.toString();
  }

  static String dedupeKey(Alert alert, Instance instance) {
    return ZapConstants.ENGINE_ID + '|' + alert.ruleId()
      + (instance == null ? "" : '|' + instance.method() + '|' + instance.uri() + '|' + instance.param());
  }

  private static void append(StringBuilder sb, String title, String html) {
    String text = stripHtml(html);
    if (!text.isEmpty()) {
      sb.append("\n\n").append(title).append(":\n").append(text);
    }
  }

  static String stripHtml(String html) {
    if (html == null) {
      return "";
    }
    return html.replaceAll("(?i)</p>|<br\\s*/?>", "\n").replaceAll("<[^>]*>", "").replaceAll("\n{3,}", "\n\n").trim();
  }

  private static String truncate(String s, int max) {
    return s.length() <= max ? s : s.substring(0, max) + "...";
  }
}
