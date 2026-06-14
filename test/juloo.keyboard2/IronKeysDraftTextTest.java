package juloo.keyboard2;

import org.junit.Test;
import static org.junit.Assert.*;

public class IronKeysDraftTextTest
{
  private static final String EMOJI = "\uD83D\uDE42";

  @Test
  public void trim_does_not_split_surrogate_pair_at_limit()
  {
    String trimmed = IronKeysDraftText.trim(repeat('a', 31) + EMOJI);

    assertEquals(repeat('a', 31), trimmed);
    assertFalse(Character.isHighSurrogate(
        trimmed.charAt(trimmed.length() - 1)));
  }

  @Test
  public void trim_keeps_complete_surrogate_pair_at_limit()
  {
    String trimmed = IronKeysDraftText.trim(repeat('a', 30) + EMOJI);

    assertEquals(repeat('a', 30) + EMOJI, trimmed);
    assertEquals(32, trimmed.length());
  }

  @Test
  public void insert_replaces_selection_and_moves_cursor_after_insertion()
  {
    IronKeysDraftText.EditResult result =
        IronKeysDraftText.insert("abcd", 1, 3, "XYZ");

    assertEdit("aXYZd", 4, result);
  }

  @Test
  public void insert_respects_limit_without_splitting_surrogate_pair()
  {
    IronKeysDraftText.EditResult result =
        IronKeysDraftText.insert(repeat('a', 31), 31, 31, EMOJI);

    assertEdit(repeat('a', 31), 31, result);
  }

  @Test
  public void insert_accepts_complete_surrogate_pair_when_it_fits()
  {
    IronKeysDraftText.EditResult result =
        IronKeysDraftText.insert(repeat('a', 30), 30, 30, EMOJI);

    assertEdit(repeat('a', 30) + EMOJI, 32, result);
  }

  @Test
  public void delete_before_removes_whole_surrogate_pair()
  {
    IronKeysDraftText.EditResult result =
        IronKeysDraftText.deleteBefore("a" + EMOJI + "b", 3, 3);

    assertEdit("ab", 1, result);
  }

  @Test
  public void delete_after_removes_whole_surrogate_pair()
  {
    IronKeysDraftText.EditResult result =
        IronKeysDraftText.deleteAfter("a" + EMOJI + "b", 1, 1);

    assertEdit("ab", 1, result);
  }

  @Test
  public void delete_removes_selected_range()
  {
    IronKeysDraftText.EditResult result =
        IronKeysDraftText.deleteBefore("abcdef", 4, 2);

    assertEdit("abef", 2, result);
  }

  private static void assertEdit(String text, int selection,
      IronKeysDraftText.EditResult result)
  {
    assertEquals(text, result.text);
    assertEquals(selection, result.selection);
  }

  private static String repeat(char c, int count)
  {
    StringBuilder builder = new StringBuilder();
    for (int i = 0; i < count; i++)
      builder.append(c);
    return builder.toString();
  }
}
