/*
 *
 * Copyright 2003-2007 Jive Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jivesoftware.smackx.vcardtemp.packet;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.DateTimeException;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jivesoftware.smack.SmackException.NoResponseException;
import org.jivesoftware.smack.SmackException.NotConnectedException;
import org.jivesoftware.smack.XMPPConnection;
import org.jivesoftware.smack.XMPPException.XMPPErrorException;
import org.jivesoftware.smack.packet.IQ;
import org.jivesoftware.smack.util.StringUtils;
import org.jivesoftware.smack.util.stringencoder.Base64;

import org.jivesoftware.smackx.vcardtemp.VCardManager;

import org.jxmpp.jid.EntityBareJid;

/**
 * A VCard class for use with the
 * <a href="http://www.jivesoftware.org/smack/" target="_blank">SMACK jabber library</a>.<p>
 *
 * You should refer to the
 * <a href="http://www.xmpp.org/extensions/jep-0054.html" target="_blank">XEP-54 documentation</a>.<p>
 *
 * Please note that this class is incomplete but it does provide the most commonly found
 * information in vCards. Also remember that VCard transfer is not a standard, and the protocol
 * may change or be replaced.<p>
 *
 * <b>Usage:</b>
 * <pre>
 *
 * // To save VCard:
 *
 * VCard vCard = new VCard();
 * vCard.setFirstName("kir");
 * vCard.setLastName("max");
 * vCard.setEmailHome("foo@fee.bar");
 * vCard.setJabberId("jabber@id.org");
 * vCard.setOrganization("Jetbrains, s.r.o");
 * vCard.setNickName("KIR");
 *
 * vCard.setTitle("Mr");
 * vCard.setAddressFieldHome("STREET", "Some street");
 * vCard.setAddressFieldWork("CTRY", "US");
 * vCard.setPhoneWork("FAX", "3443233");
 *
 * vCard.save(connection);
 *
 * // To load VCard:
 *
 * VCard vCard = new VCard();
 * vCard.load(conn); // load own VCard
 * vCard.load(conn, "joe@foo.bar"); // load someone's VCard
 * </pre>
 *
 * @author Kirill Maximov (kir@maxkir.com)
 */
public final class VCard extends IQ {
    public static final String ELEMENT = "vCard";
    public static final String NAMESPACE = "vcard-temp";

    public enum Gender { MALE, FEMALE }

    public static final class GeoPosition {
        private final float lat;
        private final float lon;

        public GeoPosition(float lat, float lon) {
            this.lat = lat;
            this.lon = lon;
        }

        public float getLat() {
            return lat;
        }

        public float getLon() {
            return lon;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null || getClass() != obj.getClass()) return false;
            GeoPosition that = (GeoPosition) obj;
            return Float.compare(that.lat, lat) == 0 && Float.compare(that.lon, lon) == 0;
        }

        @Override
        public int hashCode() {
            return Objects.hash(lat, lon);
        }

        @Override
        public String toString() {
            return lat + "," + lon;
        }
    }

    private static final Logger LOGGER = Logger.getLogger(VCard.class.getName());

    private static final String DEFAULT_MIME_TYPE = "image/jpeg";

    /**
     * Phone types:
     * VOICE?, FAX?, PAGER?, MSG?, CELL?, VIDEO?, BBS?, MODEM?, ISDN?, PCS?, PREF?
     */
    private final Map<String, String> homePhones = new HashMap<>();
    private final Map<String, String> workPhones = new HashMap<>();

    /**
     * Address types:
     * POSTAL?, PARCEL?, (DOM | INTL)?, PREF?, POBOX?, EXTADD?, STREET?, LOCALITY?,
     * REGION?, PCODE?, CTRY?
     */
    private final Map<String, String> homeAddr = new HashMap<>();
    private final Map<String, String> workAddr = new HashMap<>();

    private String firstName;
    private String lastName;
    private String middleName;
    private String prefix;
    private String suffix;

    private String emailHome;
    private String emailWork;

    private String organization;
    private String organizationUnit;

    private String photoMimeType;
    private String photoBinval;

    /**
     * Such as DESC ROLE GEO etc. see XEP-0054
     */
    private final Map<String, String> otherSimpleFields = new HashMap<>();

    // fields that, as they are should not be escaped before forwarding to the server
    private final Map<String, String> otherUnescapableFields = new HashMap<>();

    public VCard() {
        super(ELEMENT, NAMESPACE);
    }

    /**
     * Get the content of a generic VCard field.
     * You should use more specific getters instead:
     * {@link #getFullName()}
     * {@link #getTitle()}
     * {@link #getRole()}
     * {@link #getBirthday()}
     * {@link #getGender()}
     * {@link #getGeoPosition()}
     * {@link #getTimeZone()}
     * {@link #getLanguages()}
     * {@link #getUrl()}
     * {@link #getNote()}
     *
     * @param field value of field. Possible values: NICKNAME, PHOTO, BDAY, JABBERID, MAILER, TZ,
     *              GEO, TITLE, ROLE, LOGO, NOTE, PRODID, REV, SORT-STRING, SOUND, UID, URL, DESC.
     * @return content of field.
     */
    public String getField(String field) {
        return otherSimpleFields.get(field);
    }

    /**
     * Set generic VCard field.
     * You should use more specific setters instead:
     * {@link #setFullName(String)}
     * {@link #setTitle(String)}
     * {@link #setRole(String)}
     * {@link #setBirthday(LocalDate)}
     * {@link #setGender(Gender)}
     * {@link #setGeoPosition(GeoPosition)}
     * {@link #setTimeZone(ZoneId)}
     * {@link #setLanguages(List)}
     * {@link #setUrl(String)}
     * {@link #setNote(String)}
     *
     * @param value value of field
     * @param field field to set. See {@link #getField(String)}
     * @see #getField(String)
     */
    public void setField(String field, String value) {
        setField(field, value, false);
    }

    /**
     * Set generic, unescapable VCard field. If unescapable is set to true, XML maybe a part of the
     * value.
     *
     * @param value         value of field
     * @param field         field to set. See {@link #getField(String)}
     * @param isUnescapable True if the value should not be escaped, and false if it should.
     */
    public void setField(String field, String value, boolean isUnescapable) {
        if (!isUnescapable) {
            otherSimpleFields.put(field, value);
        }
        else {
            otherUnescapableFields.put(field, value);
        }
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
        // Update FN field
        updateFN();
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
        // Update FN field
        updateFN();
    }

    public String getMiddleName() {
        return middleName;
    }

    public void setMiddleName(String middleName) {
        this.middleName = middleName;
        // Update FN field
        updateFN();
    }

    public String getPrefix() {
        return prefix;
    }

    public void setPrefix(String prefix) {
        this.prefix = prefix;
        updateFN();
    }

    public String getSuffix() {
        return suffix;
    }

    public void setSuffix(String suffix) {
        this.suffix = suffix;
        updateFN();
    }

    public String getFullName() {
        return getField("FN");
    }

    /**
     * Set the FN fields with a full name (i.e., first name + middle name + last name).
     * NOTE: The FN will be overwritten on call of {@link #setFirstName(String)}, {@link #setLastName(String)} etc.
     * @param fullName the full name for FN field.
     */
    public void setFullName(String fullName) {
        setField("FN", fullName);
    }

    public String getNickName() {
        return getField("NICKNAME");
    }

    public void setNickName(String nickName) {
        setField("NICKNAME", nickName);
    }

    public String getEmailHome() {
        return emailHome;
    }

    public void setEmailHome(String email) {
        this.emailHome = email;
    }

    public String getEmailWork() {
        return emailWork;
    }

    public void setEmailWork(String emailWork) {
        this.emailWork = emailWork;
    }

    public String getJabberId() {
        return getField("JABBERID");
    }

    public void setJabberId(CharSequence jabberId) {
        setField("JABBERID", jabberId.toString());
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public String getOrganizationUnit() {
        return organizationUnit;
    }

    public void setOrganizationUnit(String organizationUnit) {
        this.organizationUnit = organizationUnit;
    }

    public String getTitle() {
        return getField("TITLE");
    }

    public void setTitle(String title) {
        setField("TITLE", title);
    }

    public String getRole() {
        return getField("ROLE");
    }

    public void setRole(String role) {
        setField("ROLE", role);
    }

    public LocalDate getBirthday() {
        String dobStr = getField("BDAY");
        return dobStr != null && !dobStr.isEmpty() ? LocalDate.parse(dobStr) : null;
    }

    public void setBirthday(LocalDate dob) {
        String dobStr = dob != null ? dob.toString() : null;
        setField("BDAY", dobStr);
    }

    public Gender getGender() {
        String genderVal = getField("GENDER");
        if (genderVal == null) {
            return null;
        }
        Gender gender = genderVal.equals("M") ? Gender.MALE : genderVal.equals("F") ? Gender.FEMALE : null;
        return gender;
    }

    public void setGender(Gender gender) {
        String genderVal = gender == Gender.MALE ? "M" : gender == Gender.FEMALE ? "F" : null;
        setField("GENDER", genderVal);
    }

    public GeoPosition getGeoPosition() {
        String geo = getField("GEO");
        if (geo == null) {
            return null;
        }
        String[] parts = geo.split(",");
        if (parts.length != 2) {
            return null;
        }
        try {
            float lat = Float.parseFloat(parts[0]);
            float lon = Float.parseFloat(parts[1]);
            if (Float.isNaN(lat) || Float.isInfinite(lat) || Float.isNaN(lon) || Float.isInfinite(lon)) {
                return null;
            }
            if (lat < -90.0 || lat > 90.0 || lon < -180.0 || lon > 180.0) {
                return null;
            }
            return new GeoPosition(lat, lon);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public void setGeoPosition(GeoPosition geoPosition) {
        String geo = geoPosition != null ? geoPosition.getLat() + "," + geoPosition.getLon() : null;
        setField("GEO", geo);
    }

    public ZoneId getTimeZone() {
        String tz = getField("TZ");
        if (tz == null) {
            return null;
        }
        try {
            return ZoneId.of(tz);
        } catch (DateTimeException e) {
            return null;
        }
    }

    public void setTimeZone(ZoneId timeZone) {
        String tz = timeZone != null ? timeZone.getId() : null;
        setField("TZ", tz);
    }

    public List<Locale> getLanguages() {
        String languages = getField("LANG");
        if (languages == null || languages.isEmpty()) {
            return null;
        }
        String[] codes = languages.split(",");
        List<Locale> locales = new ArrayList<>(codes.length);
        for (String code : codes) {
            String trimmed = code.trim();
            if (!trimmed.isEmpty()) {
                try {
                    Locale locale = Locale.forLanguageTag(trimmed);
                    locales.add(locale);
                } catch (Exception ignored) {
                    // Ignore invalid language tags
                }
            }
        }
        return locales.isEmpty() ? null : locales;
    }

    public void setLanguages(List<Locale> languages) {
        if (languages == null || languages.isEmpty()) {
            setField("LANG", null);
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (Locale locale : languages) {
            if (locale == null) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(locale.toLanguageTag());
        }
        String langVal = sb.length() > 0 ? sb.toString() : null;
        setField("LANG", langVal);
    }

    public String getUrl() {
        return getField("URL");
    }

    public void setUrl(String url) {
        setField("URL", url);
    }

    /**
     * Get the Note (Description) field. It used for bio.
     * @return value of DESC field.
     */
    public String getNote() {
        return getField("DESC");
    }

    public void setNote(String note) {
        setField("DESC", note);
    }

    /**
     * Get home address field.
     *
     * @param addrField one of POSTAL, PARCEL, (DOM | INTL), PREF, POBOX, EXTADD, STREET,
     *                  LOCALITY, REGION, PCODE, CTRY
     * @return content of home address field.
     */
    public String getAddressFieldHome(String addrField) {
        return homeAddr.get(addrField);
    }

    /**
     * Set home address field.
     *
     * @param addrField one of POSTAL, PARCEL, (DOM | INTL), PREF, POBOX, EXTADD, STREET,
     *                  LOCALITY, REGION, PCODE, CTRY
     * @param value new value for the field.
     */
    public void setAddressFieldHome(String addrField, String value) {
        homeAddr.put(addrField, value);
    }

    /**
     * Get work address field.
     *
     * @param addrField one of POSTAL, PARCEL, (DOM | INTL), PREF, POBOX, EXTADD, STREET,
     *                  LOCALITY, REGION, PCODE, CTRY
     * @return content of work address field.
     */
    public String getAddressFieldWork(String addrField) {
        return workAddr.get(addrField);
    }

    /**
     * Set work address field.
     *
     * @param addrField one of POSTAL, PARCEL, (DOM | INTL), PREF, POBOX, EXTADD, STREET,
     *                  LOCALITY, REGION, PCODE, CTRY
     * @param value new value for the field.
     */
    public void setAddressFieldWork(String addrField, String value) {
        workAddr.put(addrField, value);
    }


    /**
     * Set home phone number.
     *
     * @param phoneType one of VOICE, FAX, PAGER, MSG, CELL, VIDEO, BBS, MODEM, ISDN, PCS, PREF
     * @param phoneNum  phone number
     */
    public void setPhoneHome(String phoneType, String phoneNum) {
        homePhones.put(phoneType, phoneNum);
    }

    /**
     * Get home phone number.
     *
     * @param phoneType one of VOICE, FAX, PAGER, MSG, CELL, VIDEO, BBS, MODEM, ISDN, PCS, PREF
     * @return content of home phone number.
     */
    public String getPhoneHome(String phoneType) {
        return homePhones.get(phoneType);
    }

    /**
     * Set work phone number.
     *
     * @param phoneType one of VOICE, FAX, PAGER, MSG, CELL, VIDEO, BBS, MODEM, ISDN, PCS, PREF
     * @param phoneNum  phone number
     */
    public void setPhoneWork(String phoneType, String phoneNum) {
        workPhones.put(phoneType, phoneNum);
    }

    /**
     * Get work phone number.
     *
     * @param phoneType one of VOICE, FAX, PAGER, MSG, CELL, VIDEO, BBS, MODEM, ISDN, PCS, PREF
     * @return content of work phone number.
     */
    public String getPhoneWork(String phoneType) {
        return workPhones.get(phoneType);
    }

    /**
     * Set the avatar for the VCard by specifying the url to the image.
     *
     * @param avatarURL the url to the image(png, jpeg, gif, bmp)
     */
    public void setAvatar(URL avatarURL) {
        byte[] bytes = new byte[0];
        try {
            bytes = getBytes(avatarURL);
        }
        catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error getting bytes from URL: " + avatarURL, e);
        }

        setAvatar(bytes);
    }

    /**
     * Removes the avatar from the vCard.
     *
     *  This is done by setting the PHOTO value to the empty string as defined in XEP-0153
     */
    public void removeAvatar() {
        // Remove avatar (if any)
        photoBinval = null;
        photoMimeType = null;
    }

    /**
     * Specify the bytes of the JPEG for the avatar to use.
     * If bytes is null, then the avatar will be removed.
     * 'image/jpeg' will be used as MIME type.
     *
     * @param bytes the bytes of the avatar, or null to remove the avatar data
     */
    public void setAvatar(byte[] bytes) {
        setAvatar(bytes, DEFAULT_MIME_TYPE);
    }

    /**
     * Specify the bytes for the avatar to use as well as the mime type.
     *
     * @param bytes the bytes of the avatar.
     * @param mimeType the mime type of the avatar.
     */
    public void setAvatar(byte[] bytes, String mimeType) {
        // If bytes is null, remove the avatar
        if (bytes == null) {
            removeAvatar();
            return;
        }

        // Otherwise, add to mappings.
        String encodedImage = Base64.encodeToString(bytes);

        setAvatar(encodedImage, mimeType);
    }

    /**
     * Specify the Avatar used for this vCard.
     *
     * @param encodedImage the Base64 encoded image as String
     * @param mimeType the MIME type of the image
     */
    public void setAvatar(String encodedImage, String mimeType) {
        photoBinval = encodedImage;
        photoMimeType = mimeType;
    }

    /**
     * Set the encoded avatar string. This is used by the provider.
     *
     * @param encodedAvatar the encoded avatar string.
     * @deprecated Use {@link #setAvatar(String, String)} instead.
     */
    @Deprecated
    public void setEncodedImage(String encodedAvatar) {
        setAvatar(encodedAvatar, DEFAULT_MIME_TYPE);
    }

    /**
     * Return the byte representation of the avatar(if one exists), otherwise returns null if
     * no avatar could be found.
     * <b>Example 1</b>
     * <pre>
     * // Load Avatar from VCard
     * byte[] avatarBytes = vCard.getAvatar();
     *
     * // To create an ImageIcon for Swing applications
     * ImageIcon icon = new ImageIcon(avatar);
     *
     * // To create just an image object from the bytes
     * ByteArrayInputStream bais = new ByteArrayInputStream(avatar);
     * try {
     *   Image image = ImageIO.read(bais);
     *  }
     *  catch (IOException e) {
     *    e.printStackTrace();
     * }
     * </pre>
     *
     * @return byte representation of avatar.
     */
    public byte[] getAvatar() {
        if (photoBinval == null) {
            return null;
        }
        return Base64.decode(photoBinval);
    }

    /**
     * Returns the MIME Type of the avatar or null if none is set.
     *
     * @return the MIME Type of the avatar or null
     */
    public String getAvatarMimeType() {
        return photoMimeType;
    }

    /**
     * Common code for getting the bytes of a url.
     *
     * @param url the url to read.
     * @return bytes of the file pointed to by URL.
     * @throws IOException if an IOException occurs while reading the file.
     */
    public static byte[] getBytes(URL url) throws IOException {
        final String path = url.getPath();
        final File file = new File(path);
        if (file.exists()) {
            return getFileBytes(file);
        }

        return null;
    }

    private static byte[] getFileBytes(File file) throws IOException {
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file))) {
            int bytes = (int) file.length();
            byte[] buffer = new byte[bytes];
            int readBytes = bis.read(buffer);
            if (readBytes != buffer.length) {
                throw new IOException("Entire file not read");
            }
            return buffer;
        }
    }

    /**
     * Returns the SHA-1 Hash of the Avatar image.
     *
     * @return the SHA-1 Hash of the Avatar image.
     */
    public String getAvatarHash() {
        byte[] bytes = getAvatar();
        if (bytes == null) {
            return null;
        }

        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-1");
        }
        catch (NoSuchAlgorithmException e) {
            LOGGER.log(Level.SEVERE, "Failed to get message digest", e);
            return null;
        }

        digest.update(bytes);
        return StringUtils.encodeHex(digest.digest());
    }

    private void updateFN() {
        StringBuilder sb = new StringBuilder();
        if (firstName != null) {
            sb.append(StringUtils.escapeForXml(firstName)).append(' ');
        }
        if (middleName != null) {
            sb.append(StringUtils.escapeForXml(middleName)).append(' ');
        }
        if (lastName != null) {
            sb.append(StringUtils.escapeForXml(lastName));
        }
        setFullName(sb.toString());
    }

    /**
     * Save this vCard for the user connected by 'connection'. XMPPConnection should be authenticated
     * and not anonymous.
     *
     * @param connection the XMPPConnection to use.
     * @throws XMPPErrorException thrown if there was an issue setting the VCard in the server.
     * @throws NoResponseException if there was no response from the server.
     * @throws NotConnectedException if the XMPP connection is not connected.
     * @throws InterruptedException if the calling thread was interrupted.
     * @deprecated use {@link VCardManager#saveVCard(VCard)} instead.
     */
    @Deprecated
    public void save(XMPPConnection connection) throws NoResponseException, XMPPErrorException, NotConnectedException, InterruptedException {
        VCardManager.getInstanceFor(connection).saveVCard(this);
    }

    /**
     * Load VCard information for a connected user. XMPPConnection should be authenticated
     * and not anonymous.
     *
     * @param connection connection.
     * @throws XMPPErrorException if there was an XMPP error returned.
     * @throws NoResponseException if there was no response from the remote entity.
     * @throws NotConnectedException if the XMPP connection is not connected.
     * @throws InterruptedException if the calling thread was interrupted.
     * @deprecated use {@link VCardManager#loadVCard()} instead.
     */
    @Deprecated
    public void load(XMPPConnection connection) throws NoResponseException, XMPPErrorException, NotConnectedException, InterruptedException  {
        load(connection, null);
    }

    /**
     * Load VCard information for a given user. XMPPConnection should be authenticated and not anonymous.
     *
     * @param connection connection.
     * @param user user whose information we want to load.
     *
     * @throws XMPPErrorException if there was an XMPP error returned.
     * @throws NoResponseException if there was no response from the server.
     * @throws NotConnectedException if the XMPP connection is not connected.
     * @throws InterruptedException if the calling thread was interrupted.
     * @deprecated use {@link VCardManager#loadVCard(EntityBareJid)} instead.
     */
    @Deprecated
    public void load(XMPPConnection connection, EntityBareJid user) throws NoResponseException, XMPPErrorException, NotConnectedException, InterruptedException {
        VCard result = VCardManager.getInstanceFor(connection).loadVCard(user);
        copyFieldsFrom(result);
    }

    @Override
    protected IQChildElementXmlStringBuilder getIQChildElementBuilder(IQChildElementXmlStringBuilder xml) {
        if (!hasContent()) {
            xml.setEmptyElement();
            return xml;
        }
        xml.rightAngleBracket();
        if (hasNameField()) {
            xml.openElement("N");
            xml.optElement("FAMILY", lastName);
            xml.optElement("GIVEN", firstName);
            xml.optElement("MIDDLE", middleName);
            xml.optElement("PREFIX", prefix);
            xml.optElement("SUFFIX", suffix);
            xml.closeElement("N");
        }
        if (hasOrganizationFields()) {
            xml.openElement("ORG");
            xml.optElement("ORGNAME", organization);
            xml.optElement("ORGUNIT", organizationUnit);
            xml.closeElement("ORG");
        }
        for (Map.Entry<String, String> entry : otherSimpleFields.entrySet()) {
            xml.optElement(entry.getKey(), entry.getValue());
        }
        for (Map.Entry<String, String> entry : otherUnescapableFields.entrySet()) {
            final String value = entry.getValue();
            if (value == null) {
                continue;
            }
            xml.openElement(entry.getKey());
            xml.append(value);
            xml.closeElement(entry.getKey());
        }
        if (photoBinval != null) {
            xml.openElement("PHOTO");
            xml.escapedElement("BINVAL", photoBinval);
            xml.element("TYPE", photoMimeType);
            xml.closeElement("PHOTO");
        }
        if (emailWork != null) {
            xml.openElement("EMAIL");
            xml.emptyElement("WORK");
            xml.emptyElement("INTERNET");
            xml.emptyElement("PREF");
            xml.element("USERID", emailWork);
            xml.closeElement("EMAIL");
        }
        if (emailHome != null) {
            xml.openElement("EMAIL");
            xml.emptyElement("HOME");
            xml.emptyElement("INTERNET");
            xml.emptyElement("PREF");
            xml.element("USERID", emailHome);
            xml.closeElement("EMAIL");
        }
        for (Map.Entry<String, String> phone : workPhones.entrySet()) {
            final String number = phone.getValue();
            if (number == null) {
                continue;
            }
            xml.openElement("TEL");
            xml.emptyElement("WORK");
            xml.emptyElement(phone.getKey());
            xml.element("NUMBER", number);
            xml.closeElement("TEL");
        }
        for (Map.Entry<String, String> phone : homePhones.entrySet()) {
            final String number = phone.getValue();
            if (number == null) {
                continue;
            }
            xml.openElement("TEL");
            xml.emptyElement("HOME");
            xml.emptyElement(phone.getKey());
            xml.element("NUMBER", number);
            xml.closeElement("TEL");
        }
        if (!workAddr.isEmpty()) {
            xml.openElement("ADR");
            xml.emptyElement("WORK");
            for (Map.Entry<String, String> entry : workAddr.entrySet()) {
                final String value = entry.getValue();
                if (value == null) {
                    continue;
                }
                xml.element(entry.getKey(), value);
            }
            xml.closeElement("ADR");
        }
        if (!homeAddr.isEmpty()) {
            xml.openElement("ADR");
            xml.emptyElement("HOME");
            for (Map.Entry<String, String> entry : homeAddr.entrySet()) {
                final String value = entry.getValue();
                if (value == null) {
                    continue;
                }
                xml.element(entry.getKey(), value);
            }
            xml.closeElement("ADR");
        }
        return xml;
    }

    private void copyFieldsFrom(VCard from) {
        Field[] fields = VCard.class.getDeclaredFields();
        for (Field field : fields) {
            if (field.getDeclaringClass() == VCard.class &&
                    !Modifier.isFinal(field.getModifiers())) {
                try {
                    field.setAccessible(true);
                    field.set(this, field.get(from));
                }
                catch (IllegalAccessException e) {
                    throw new RuntimeException("This cannot happen:" + field, e);
                }
            }
        }
    }

    private boolean hasContent() {
        // noinspection OverlyComplexBooleanExpression
        return hasNameField()
                || hasOrganizationFields()
                || emailHome != null
                || emailWork != null
                || otherSimpleFields.size() > 0
                || otherUnescapableFields.size() > 0
                || homeAddr.size() > 0
                || homePhones.size() > 0
                || workAddr.size() > 0
                || workPhones.size() > 0
                || photoBinval != null
                ;
    }

    private boolean hasNameField() {
        return firstName != null || lastName != null || middleName != null
                || prefix != null || suffix != null;
    }

    private boolean hasOrganizationFields() {
        return organization != null || organizationUnit != null;
    }

    // Used in tests:

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        final VCard vCard = (VCard) o;

        if (emailHome != null ? !emailHome.equals(vCard.emailHome) : vCard.emailHome != null) {
            return false;
        }
        if (emailWork != null ? !emailWork.equals(vCard.emailWork) : vCard.emailWork != null) {
            return false;
        }
        if (firstName != null ? !firstName.equals(vCard.firstName) : vCard.firstName != null) {
            return false;
        }
        if (!homeAddr.equals(vCard.homeAddr)) {
            return false;
        }
        if (!homePhones.equals(vCard.homePhones)) {
            return false;
        }
        if (lastName != null ? !lastName.equals(vCard.lastName) : vCard.lastName != null) {
            return false;
        }
        if (middleName != null ? !middleName.equals(vCard.middleName) : vCard.middleName != null) {
            return false;
        }
        if (organization != null ?
                !organization.equals(vCard.organization) : vCard.organization != null) {
            return false;
        }
        if (organizationUnit != null ?
                !organizationUnit.equals(vCard.organizationUnit) : vCard.organizationUnit != null) {
            return false;
        }
        if (!otherSimpleFields.equals(vCard.otherSimpleFields)) {
            return false;
        }
        if (!workAddr.equals(vCard.workAddr)) {
            return false;
        }
        if (photoBinval != null ? !photoBinval.equals(vCard.photoBinval) : vCard.photoBinval != null) {
            return false;
        }

        return workPhones.equals(vCard.workPhones);
    }

    @Override
    public int hashCode() {
        int result;
        result = homePhones.hashCode();
        result = 29 * result + workPhones.hashCode();
        result = 29 * result + homeAddr.hashCode();
        result = 29 * result + workAddr.hashCode();
        result = 29 * result + (firstName != null ? firstName.hashCode() : 0);
        result = 29 * result + (lastName != null ? lastName.hashCode() : 0);
        result = 29 * result + (middleName != null ? middleName.hashCode() : 0);
        result = 29 * result + (emailHome != null ? emailHome.hashCode() : 0);
        result = 29 * result + (emailWork != null ? emailWork.hashCode() : 0);
        result = 29 * result + (organization != null ? organization.hashCode() : 0);
        result = 29 * result + (organizationUnit != null ? organizationUnit.hashCode() : 0);
        result = 29 * result + otherSimpleFields.hashCode();
        result = 29 * result + (photoBinval != null ? photoBinval.hashCode() : 0);
        return result;
    }

}

