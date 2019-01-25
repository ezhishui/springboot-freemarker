package cn.springboot.common.authority.service.xss;

import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import javax.servlet.FilterConfig;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.ResourceUtils;

/**
 * @Description 安全过滤配置管理类
 * @author 王鑫
 * @date Mar 24, 2017 7:45:22 PM
 */
@SuppressWarnings("all")
public class XSSSecurityManager {

	private static final Logger log = LoggerFactory.getLogger(XSSSecurityManager.class);

	public static Set<String> whiteUrls = new HashSet<>();
//	public static Set<Pattern> patterns = new HashSet<>();
	public static Map<String,Pattern> regexAndPatternMap = new HashMap<>();

	/**
	 * 特殊字符匹配
	 */
	private static Pattern XSS_PATTERN;

	/**
	 * 特殊url匹配规则map，<url,regex>
	 */
	public static List<Map<String, Object>> checkUrlMatcherList = new ArrayList<Map<String, Object>>();

	/**
	 * Constructor
	 */
	private XSSSecurityManager() {
	}

	/**
	 * 初始化
	 *
	 * @param config
	 *            配置参数
	 */
	public static void init(FilterConfig config) {

		log.debug("XSSSecurityManager init(FilterConfig config) begin");
		log.debug("xss classpath={}", config.getInitParameter("securityconfig"));
		// 初始化安全过滤配置
		try {
			URL xssPath = ResourceUtils.getURL(config.getInitParameter("securityconfig"));
			log.debug("xss URL={}", xssPath);
			initConfig(xssPath);
		} catch (DocumentException e) {
			log.error("安全过滤配置文件xss_security_config.xml加载异常");
		} catch (IOException e) {
			log.error("安全过滤配置文件xss_security_config.xml加载异常");
		}
		log.debug("XSSSecurityManager init(FilterConfig config) end");
	}

	/**
	 * 读取安全审核配置文件xss_security_config.xml 设置XSSSecurityConfig配置信息
	 *
	 * @param path
	 *            过滤配置文件路径
	 * @return ture or false
	 * @throws DocumentException
	 */
	public static boolean initConfig(URL url) throws DocumentException {
		log.debug("XSSSecurityManager.initConfig(URL url) begin");
		Element superElement = new SAXReader().read(url).getRootElement();
		XSSSecurityConfig.IS_CHECK_HEADER = new Boolean(
				getEleValue(superElement, XSSSecurityConstants.IS_CHECK_HEADER));
		XSSSecurityConfig.IS_CHECK_PARAMETER = new Boolean(
				getEleValue(superElement, XSSSecurityConstants.IS_CHECK_PARAMETER));
		XSSSecurityConfig.IS_CHECK_URL = new Boolean(getEleValue(superElement, XSSSecurityConstants.IS_CHECK_URL));
		XSSSecurityConfig.IS_LOG = new Boolean(getEleValue(superElement, XSSSecurityConstants.IS_LOG));
		XSSSecurityConfig.IS_CHAIN = new Boolean(getEleValue(superElement, XSSSecurityConstants.IS_CHAIN));
		XSSSecurityConfig.REPLACE = new Boolean(getEleValue(superElement, XSSSecurityConstants.REPLACE));

		Element whiteUrlList = superElement.element(XSSSecurityConstants.WHITE_URL_LIST);

		// 加载白名单url过滤配置
		if (whiteUrlList != null) {
			List<Element> urls = whiteUrlList.elements(XSSSecurityConstants.CHECK_URL_URL);
			if(CollectionUtils.isNotEmpty(urls)){
				for (Element e : urls) {
					String urlValue = e.getStringValue();
					if (StringUtils.isNotBlank(urlValue)) {
						log.info("配置的白名单url:{}", urlValue);
						XSSSecurityManager.whiteUrls.add(urlValue);
					}
				}
			}
		}

		// 加载通用通用正则过滤配置
		Element regexEleList = superElement.element(XSSSecurityConstants.REGEX_LIST);
		if (regexEleList != null) {
			List<Element> regexEles = regexEleList.elements(XSSSecurityConstants.CHECK_URL_REGEX);
			if(CollectionUtils.isNotEmpty(regexEles)){
				for(Element e : regexEles){
					String regValue = e.getStringValue();
					// xml的cdata标签传输数据时，会默认在\前加\，需要将\\替换为\
					regValue = regValue.replaceAll("\\\\\\\\", "\\\\");
					if (StringUtils.isNotBlank(regValue)) {
						log.info("配置的匹配规则:{}", regValue);
						Pattern p = Pattern.compile(regValue);
						XSSSecurityManager.regexAndPatternMap.put(regValue, p);
					}
				}
			}
		} else {
			log.error("安全过滤配置文件中没有 " + XSSSecurityConstants.REGEX_LIST + " 属性");
			return false;
		}

		log.debug("XSSSecurityManager.initConfig(String path) end");
		return true;

	}

	/**
	 * 从目标element中获取指定标签信息，若找不到该标签，记录错误日志
	 * 
	 * @param element
	 *            目标节点
	 * @param tagName
	 *            制定标签
	 * @return
	 */
	private static String getEleValue(Element element, String tagName) {
		if (isNullStr(element.elementText(tagName))) {
			log.debug("安全过滤配置文件中没有 " + XSSSecurityConstants.REGEX_LIST + " 属性");
		}
		return element.elementText(tagName);
	}

	/**
	 * 对非法字符进行替换-会替换掉符合正则的整个字符串
	 *
	 * @param text
	 * @return
	 */
	public static String securityReplace(String text) {
		if (isNullStr(text)) {
			return text;
		} else {
			return text.replaceAll(REGEX, XSSSecurityConstants.REPLACEMENT);
		}
	}

	/**
	 * 匹配字符是否含特殊字符
	 * 
	 * @param text
	 * @return
	 */
	public static boolean matches(String text) {
		if (text == null) {
			return false;
		}
		return XSS_PATTERN.matcher(text).matches();
	}

	/**
	 * 释放关键信息
	 */
	public static void destroy() {
		log.debug("XSSSecurityManager.destroy() begin");
		XSS_PATTERN = null;
		REGEX = null;
		log.debug("XSSSecurityManager.destroy() end");
	}

	/**
	 * 判断是否为空串，建议放到某个工具类中
	 * 
	 * @param value
	 * @return
	 */
	public static boolean isNullStr(String value) {
		return value == null || value.trim().equals("");
	}
}
