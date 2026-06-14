package juloo.keyboard2;

import juloo.keyboard2.ironkeys.IronKeysMessageCipher;

final class IronKeysDraftText
{
  private IronKeysDraftText() {}

  static String trim(String text)
  {
    return trim(text, IronKeysMessageCipher.MAX_PLAINTEXT_CHARS);
  }

  static String trim(String text, int maxChars)
  {
    if (text == null)
      return "";
    if (maxChars <= 0)
      return "";
    if (text.length() <= maxChars)
      return text;
    int end = Math.min(maxChars, text.length());
    if (end > 0 && end < text.length() &&
        Character.isHighSurrogate(text.charAt(end - 1)) &&
        Character.isLowSurrogate(text.charAt(end)))
      end--;
    return text.substring(0, end);
  }

  static EditResult insert(String text, int selectionStart, int selectionEnd,
      String insertion)
  {
    String value = normalize(text);
    Selection selection = normalizedSelection(value, selectionStart,
        selectionEnd);
    if (insertion == null || insertion.length() == 0)
      return new EditResult(value, selection.end);

    int replacementBudget = IronKeysMessageCipher.MAX_PLAINTEXT_CHARS -
        (value.length() - (selection.end - selection.start));
    if (replacementBudget <= 0)
      return new EditResult(value, selection.end);

    String inserted = trim(insertion, replacementBudget);
    String edited = value.substring(0, selection.start) + inserted +
        value.substring(selection.end);
    return new EditResult(edited, selection.start + inserted.length());
  }

  static EditResult deleteBefore(String text, int selectionStart,
      int selectionEnd)
  {
    String value = normalize(text);
    Selection selection = normalizedSelection(value, selectionStart,
        selectionEnd);
    if (selection.start != selection.end)
    {
      String edited = value.substring(0, selection.start) +
          value.substring(selection.end);
      return new EditResult(edited, selection.start);
    }
    if (selection.start <= 0)
      return new EditResult(value, selection.start);

    int deleteStart = selection.start - 1;
    if (deleteStart > 0 &&
        Character.isLowSurrogate(value.charAt(deleteStart)) &&
        Character.isHighSurrogate(value.charAt(deleteStart - 1)))
      deleteStart--;
    String edited = value.substring(0, deleteStart) +
        value.substring(selection.start);
    return new EditResult(edited, deleteStart);
  }

  static EditResult deleteAfter(String text, int selectionStart,
      int selectionEnd)
  {
    String value = normalize(text);
    Selection selection = normalizedSelection(value, selectionStart,
        selectionEnd);
    if (selection.start != selection.end)
    {
      String edited = value.substring(0, selection.start) +
          value.substring(selection.end);
      return new EditResult(edited, selection.start);
    }
    if (selection.end >= value.length())
      return new EditResult(value, selection.end);

    int deleteEnd = selection.end + 1;
    if (deleteEnd < value.length() &&
        Character.isHighSurrogate(value.charAt(selection.end)) &&
        Character.isLowSurrogate(value.charAt(deleteEnd)))
      deleteEnd++;
    String edited = value.substring(0, selection.end) +
        value.substring(deleteEnd);
    return new EditResult(edited, selection.end);
  }

  private static String normalize(String text)
  {
    return text == null ? "" : text;
  }

  private static Selection normalizedSelection(String text, int start, int end)
  {
    if (start < 0 || end < 0)
      return new Selection(text.length(), text.length());
    int normalizedStart = Math.min(start, end);
    int normalizedEnd = Math.max(start, end);
    normalizedStart = Math.min(normalizedStart, text.length());
    normalizedEnd = Math.min(normalizedEnd, text.length());
    return new Selection(normalizedStart, normalizedEnd);
  }

  static final class EditResult
  {
    final String text;
    final int selection;

    EditResult(String text, int selection)
    {
      this.text = text;
      this.selection = selection;
    }
  }

  private static final class Selection
  {
    final int start;
    final int end;

    Selection(int start, int end)
    {
      this.start = start;
      this.end = end;
    }
  }
}
