package edu.cnm.deepdive.security;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.ResourceBundle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The <code>Diceware</code> class implements a Diceware-based passphrase generator, using a word
 * list provided by invoking a word list in the constructor. If a psuedo-random number generator is
 * not set (using {@link Diceware#setRng(Random)} method) then an instance of {@link SecureRandom}
 * is created and used for selecting words at random from the list.
 * 
 * @author D Stout with Deep Dive Coding Java Cohort 3
 * @version 0.2
 */
public class Diceware {

  private static final String DEFAULT_RESOURCE_BUNDLE = "wordlist";
  private static final String NEGATIVE_PASSPHRASE_MESSAGE = "Passphrase length must be positive!";
  private static final String LINE_PATTERN = "^\\s*(\\d+)\\s+(\\S+)\\s*$";

  private List<String> words;
  private Random rng = null;

/**
 * An overloaded Constructor Initializes an instance of <code>Diceware</code> that calls
 * the Constructor that takes a {@link ResourceBundle} using the wordlist.
 */
  public Diceware() {
    this(ResourceBundle.getBundle(DEFAULT_RESOURCE_BUNDLE));
  }


  /**
   * Initializes an instance of <code>Diceware</code> using a reference to a {@link java.io.File}
   * object. If the <code>File</code> does not exist or cannot be read, and exception will be
   * thrown.
   * 
   * @param file file to read for word list.
   * @throws FileNotFoundException if file does not exist.
   * @throws IOException if file can't be read.
   */
  public Diceware(File file) throws FileNotFoundException, IOException {
    words = new ArrayList<>();
    try (FileInputStream input = new FileInputStream(file);
        InputStreamReader reader = new InputStreamReader(input);
        BufferedReader buffer = new BufferedReader(reader);) {
      Pattern p = Pattern.compile(LINE_PATTERN);
      for (String line = buffer.readLine(); line != null; line = buffer.readLine()) {
        Matcher m = p.matcher(line);
        if (m.matches()) {
          words.add(m.group(2));
        }
      }
    }
  }

  /**
   * Initializes an instance of <code>Diceware</code> using a {@link Collection String} object as
   * the source of words for the word list.
   * 
   * @param source word list source.
   */
  public Diceware(Collection<String> source) {
    words = new ArrayList<>(source);
  }

  /**
   * Initializes an instance of <code>Diceware</code> using a {@link ResourceBundle} object as the
   * source of words for the word list. (The property values from the <code>ResourceBundle</code>
   * are taken as the words; the property names/keys are ignored.)
   * 
   * @param bundle bundles the words in the list provided
   */
  public Diceware(ResourceBundle bundle) {
    words = new ArrayList<>();
    Enumeration<String> en = bundle.getKeys();
    while (en.hasMoreElements()) {
      words.add(bundle.getString(en.nextElement()));
    }
  }

  /**
   * Initializes <code>SecureRandom</code> if random number generator has not been initialized
   * already.
   * 
   * @return psudeo-random number generator instance.
   * @throws NoSuchAlgorithmException if lazy initialization is used, and default strong provider
   *         algorithm.
   */
  public Random getRng() throws NoSuchAlgorithmException {
    if (rng == null) {
      rng = SecureRandom.getInstanceStrong();
    }
    return rng;
  }

  /**
   * Sets the <code>rng</code> for the field.
   * 
   * @param rng psudeo-random number generator instance
   */
  public void setRng(Random rng) {
    this.rng = rng;
  }

  /**
   * Generates and returns returns (in a <code>String[]</code>) a password of the specified length.
   * The inclusion of duplicates is controlled by the <code>duplicatesAllowed</code> argument. If
   * the specified length is greater than the number of words in the word list, and duplicates
   * aren't allowed then an infinite loop will result.
   * 
   * @param length number of words to include in generated passphrase.
   * @param duplicatesAllowed if true will allow duplicates of words.
   * @return words in generated passphrase.
   * @throws NoSuchAlgorithmException if algorithm for randomness not allowed.
   * 
   * @throws InsufficientPoolException if password length exceeds word list, and duplicates not
   *         allowed or word list has no words.
   * 
   * @throws IllegalArgumentException if requested length is negative.
   */
  public String[] generate(int length, boolean duplicatesAllowed)
      throws NoSuchAlgorithmException, InsufficientPoolException, IllegalArgumentException {
    if (length <= 0) {
      throw new IllegalArgumentException(NEGATIVE_PASSPHRASE_MESSAGE);
    }
    if ((words.size() == 0 && length > 0) || (!duplicatesAllowed && length > words.size())) {
      throw new InsufficientPoolException();
    }
    List<String> passphrase = new LinkedList<>();
    while (passphrase.size() < length) {
      String word = generate();
      if (duplicatesAllowed || !passphrase.contains(word)) {
        passphrase.add(word);
      }
    }
    return passphrase.toArray(new String[passphrase.size()]);
  }

/**
 * A method that takes an int and a String as parameters and generates a passphrase
 * with how many words chosen by the int provided and the delimiter provided is the String that
 * will be placed in between each word.
 * 
 * @param length                      the amount of words you want provided
 * @param delimiter                   any character that you want in between each word (e.g. "-")
 * @return                            returns the number of words, what characters should be inserted
 *                                    between words, and true indicates that duplicate words will not be
 *                                    allowed. 
 * @throws NoSuchAlgorithmException   throws an exception if randomness is not allowed.
 * @throws InsufficientPoolException  throws an exception if more words are asked for than are in
 *                                    the wordlist provided, duplicates must be taken into account.
 * @throws IllegalArgumentException   throws an exception if the requested amount of words is not
 *                                    positive.
 */
  public String generate(int length, String delimiter)
      throws NoSuchAlgorithmException, InsufficientPoolException, IllegalArgumentException {
    return generate(length, delimiter, true);
  }


  /**
   * Generates and returns (in a <code>String[]</code>) a password of the specified length. This
   * method invokes {@link #generate(int, boolean) generate (length, true)} &ndash; that is, it
   * invokes {@link #generate(int, boolean)}, specifying that duplicates are allowed.
   * 
   * @param length number of words to include in generated passphrase.
   * @return words in a generated passphrase.
   * @throws NoSuchAlgorithmException if algorithm randomness not allowed.
   * 
   * @throws InsufficientPoolException if word list has no words.
   * 
   * @throws IllegalArgumentException if requested length isn't positive.
   */
  public String[] generate(int length)
      throws NoSuchAlgorithmException, InsufficientPoolException, IllegalArgumentException {
    return generate(length, true);
  }

  
  /**
   * A method that generates a passphrase including an int for the amount of words in the
   * passphrase, a String for any characters you would like between the words, and a boolean
   * to declare whether you would like to include duplicate words or not. It uses a String Array
   * to form the grouping of words a {@link StringBuilder} to place the words in a new array
   * and outputs the passphrase in a String Array format.
   * 
   * @param length                      the amount of words you want provided
   * @param delimiter                   any character that you want in between each word (e.g. "-")
   * @param duplicatesAllowed           if duplicate words should be allowed.
   * @return                            Returns the number of words, what characters should be inserted
   *                                    between words, and true indicates that duplicate words will not be
   *                                    allowed. 
   * @throws NoSuchAlgorithmException   throws an exception if randomness is not allowed.
   * @throws InsufficientPoolException  throws an exception if more words are asked for than are in
   *                                    the wordlist provided, duplicates must be taken into account.
   * @throws IllegalArgumentException   throws an exception if the requested amount of words is not
   *                                    positive.
   */
  public String generate(int length, String delimiter, boolean duplicatesAllowed)
      throws NoSuchAlgorithmException, InsufficientPoolException, IllegalArgumentException {
    String[] words = generate(length, duplicatesAllowed);
    StringBuilder builder = new StringBuilder(words[0]);
    for (int i = 1; i < words.length; i++) {
      builder.append(delimiter);
      builder.append(words[i]);
    }
    return builder.toString();
  }

  private String generate() throws NoSuchAlgorithmException {
    int index = getRng().nextInt(words.size());
    return words.get(index);
  }

  /**
   * A nested class that extends {@link IllegalArgumentException} to handle the 
   * {@link InsufficientPoolException} that is thrown.
   *
   */
  public static class InsufficientPoolException extends IllegalArgumentException {

    private InsufficientPoolException() {

    }
  }

}
