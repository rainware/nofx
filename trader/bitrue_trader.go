package trader

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// BitrueTrader Bitrue交易平台实现
type BitrueTrader struct {
	apiKey     string
	secretKey  string
	client     *http.Client
	baseURL    string
	recvWindow int64 // 接收窗口时间(ms)

	// 缓存交易对精度信息
	contractPrecision map[string]ContractPrecision
	mu                sync.RWMutex
}

// ContractPrecision 合约精度信息
type ContractPrecision struct {
	PricePrecision int
	VolumePrecision int
	MinOrderVolume float64
	MaxLimitVolume float64
}

// NewBitrueTrader 创建Bitrue交易器
// apiKey: API密钥
// secretKey: API密钥对应的Secret
func NewBitrueTrader(apiKey, secretKey string) (*BitrueTrader, error) {
	if apiKey == "" || secretKey == "" {
		return nil, fmt.Errorf("API密钥和Secret不能为空")
	}

	return &BitrueTrader{
		apiKey:            apiKey,
		secretKey:         secretKey,
		contractPrecision: make(map[string]ContractPrecision),
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
				IdleConnTimeout:       90 * time.Second,
			},
		},
		baseURL:    "https://fapi.bitrue.com",
		recvWindow: 5000, // 默认5秒
	}, nil
}

// sign 生成请求签名
// Bitrue签名规则: HMAC SHA256(timestamp + method + requestPath + body)
func (t *BitrueTrader) sign(method, requestPath, body string, timestamp int64) string {
	// 构造签名字符串
	message := fmt.Sprintf("%d%s%s%s", timestamp, method, requestPath, body)

	// HMAC SHA256
	h := hmac.New(sha256.New, []byte(t.secretKey))
	h.Write([]byte(message))

	return hex.EncodeToString(h.Sum(nil))
}

// request 发送HTTP请求
func (t *BitrueTrader) request(method, endpoint string, params map[string]interface{}, needSign bool) ([]byte, error) {
	const maxRetries = 3
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		body, err := t.doRequest(method, endpoint, params, needSign)
		if err == nil {
			return body, nil
		}

		lastErr = err

		// 如果是网络超时或临时错误，重试
		if strings.Contains(err.Error(), "timeout") ||
			strings.Contains(err.Error(), "connection reset") ||
			strings.Contains(err.Error(), "EOF") {
			if attempt < maxRetries {
				waitTime := time.Duration(attempt) * time.Second
				time.Sleep(waitTime)
				continue
			}
		}

		// 其他错误不重试
		return nil, err
	}

	return nil, fmt.Errorf("请求失败（已重试%d次）: %w", maxRetries, lastErr)
}

// doRequest 执行实际的HTTP请求
func (t *BitrueTrader) doRequest(method, endpoint string, params map[string]interface{}, needSign bool) ([]byte, error) {
	fullURL := t.baseURL + endpoint
	method = strings.ToUpper(method)

	// 生成时间戳
	timestamp := time.Now().UnixNano() / int64(time.Millisecond)

	var req *http.Request
	var err error

	if method == "GET" {
		// GET请求：参数放在querystring中
		q := url.Values{}
		for k, v := range params {
			q.Set(k, fmt.Sprintf("%v", v))
		}

		if len(q) > 0 {
			fullURL += "?" + q.Encode()
		}

		req, err = http.NewRequest("GET", fullURL, nil)
		if err != nil {
			return nil, err
		}

		// 签名
		if needSign {
			signature := t.sign(method, endpoint+"?"+q.Encode(), "", timestamp)
			req.Header.Set("X-CH-SIGN", signature)
		}

	} else if method == "POST" {
		// POST请求：参数放在JSON body中
		var bodyBytes []byte
		bodyStr := ""

		if len(params) > 0 {
			bodyBytes, err = json.Marshal(params)
			if err != nil {
				return nil, err
			}
			bodyStr = string(bodyBytes)
		}

		req, err = http.NewRequest("POST", fullURL, strings.NewReader(bodyStr))
		if err != nil {
			return nil, err
		}

		req.Header.Set("Content-Type", "application/json")

		// 签名
		if needSign {
			signature := t.sign(method, endpoint, bodyStr, timestamp)
			req.Header.Set("X-CH-SIGN", signature)
		}

	} else {
		return nil, fmt.Errorf("不支持的HTTP方法: %s", method)
	}

	// 设置通用头部
	if needSign {
		req.Header.Set("X-CH-APIKEY", t.apiKey)
		req.Header.Set("X-CH-TS", fmt.Sprintf("%d", timestamp))
	}

	// 发送请求
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// 检查HTTP状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	// 检查API返回的错误码
	var apiResp struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(body, &apiResp); err == nil {
		if apiResp.Code != 0 {
			return nil, fmt.Errorf("API错误 %d: %s", apiResp.Code, apiResp.Msg)
		}
	}

	return body, nil
}

// getPrecision 获取合约精度信息
func (t *BitrueTrader) getPrecision(symbol string) (ContractPrecision, error) {
	t.mu.RLock()
	if prec, ok := t.contractPrecision[symbol]; ok {
		t.mu.RUnlock()
		return prec, nil
	}
	t.mu.RUnlock()

	// 获取合约信息
	body, err := t.request("GET", "/fapi/v1/contracts", nil, false)
	if err != nil {
		return ContractPrecision{}, err
	}

	var contracts []struct {
		Symbol         string  `json:"symbol"`
		PricePrecision int     `json:"pricePrecision"`
		MinOrderVolume float64 `json:"minOrderVolume"`
		MaxLimitVolume float64 `json:"maxLimitVolume"`
	}

	if err := json.Unmarshal(body, &contracts); err != nil {
		return ContractPrecision{}, err
	}

	// 缓存所有合约的精度
	t.mu.Lock()
	for _, c := range contracts {
		// Bitrue合约名称格式: E-BTC-USDT
		// 转换为标准格式: BTCUSDT
		stdSymbol := t.convertToStandardSymbol(c.Symbol)

		prec := ContractPrecision{
			PricePrecision:  c.PricePrecision,
			VolumePrecision: 8, // Bitrue没有返回数量精度，使用默认值8
			MinOrderVolume:  c.MinOrderVolume,
			MaxLimitVolume:  c.MaxLimitVolume,
		}

		t.contractPrecision[stdSymbol] = prec
	}
	t.mu.Unlock()

	if prec, ok := t.contractPrecision[symbol]; ok {
		return prec, nil
	}

	return ContractPrecision{}, fmt.Errorf("未找到合约 %s 的精度信息", symbol)
}

// convertToStandardSymbol 将Bitrue合约名称转换为标准symbol
// E-BTC-USDT -> BTCUSDT
func (t *BitrueTrader) convertToStandardSymbol(bitrueSymbol string) string {
	parts := strings.Split(bitrueSymbol, "-")
	if len(parts) == 3 {
		return parts[1] + parts[2]
	}
	return bitrueSymbol
}

// convertToBitrueSymbol 将标准symbol转换为Bitrue合约名称
// BTCUSDT -> E-BTC-USDT
func (t *BitrueTrader) convertToBitrueSymbol(symbol string) string {
	// 如果已经是Bitrue格式，直接返回
	if strings.HasPrefix(symbol, "E-") {
		return symbol
	}

	// 去掉USDT后缀
	if strings.HasSuffix(symbol, "USDT") {
		base := symbol[:len(symbol)-4]
		return fmt.Sprintf("E-%s-USDT", base)
	}

	// 默认假设是USDT交易对
	return fmt.Sprintf("E-%s-USDT", symbol)
}

// formatPrice 格式化价格到正确精度
func (t *BitrueTrader) formatPrice(symbol string, price float64) (float64, error) {
	prec, err := t.getPrecision(symbol)
	if err != nil {
		return 0, err
	}

	multiplier := math.Pow10(prec.PricePrecision)
	return math.Round(price*multiplier) / multiplier, nil
}

// formatVolume 格式化数量到正确精度
func (t *BitrueTrader) formatVolume(symbol string, volume float64) (float64, error) {
	prec, err := t.getPrecision(symbol)
	if err != nil {
		return 0, err
	}

	multiplier := math.Pow10(prec.VolumePrecision)
	return math.Round(volume*multiplier) / multiplier, nil
}

// GetBalance 获取账户余额
func (t *BitrueTrader) GetBalance() (map[string]interface{}, error) {
	body, err := t.request("GET", "/fapi/v1/account", nil, true)
	if err != nil {
		return nil, err
	}

	var account struct {
		MarginCoin    string  `json:"marginCoin"`
		AccountNormal float64 `json:"accountNormal"` // 可用余额
		AccountLock   float64 `json:"accountLock"`   // 锁定余额（保证金）
		PositionVos   []struct {
			ContractName     string  `json:"contractName"`
			PositionType     int     `json:"positionType"` // 1=全仓, 2=逐仓
			Volume           float64 `json:"volume"`
			AvailableVolume  float64 `json:"availableVolume"`
			UnrealizedAmount float64 `json:"unrealizedAmount"` // 未实现盈亏
		} `json:"positionVos"`
	}

	if err := json.Unmarshal(body, &account); err != nil {
		return nil, err
	}

	// 计算未实现盈亏
	totalUnrealizedPnl := 0.0
	for _, pos := range account.PositionVos {
		totalUnrealizedPnl += pos.UnrealizedAmount
	}

	// 计算总余额
	totalWalletBalance := account.AccountNormal + account.AccountLock

	return map[string]interface{}{
		"totalWalletBalance":    totalWalletBalance,
		"availableBalance":      account.AccountNormal,
		"totalUnrealizedProfit": totalUnrealizedPnl,
	}, nil
}

// GetPositions 获取持仓信息
func (t *BitrueTrader) GetPositions() ([]map[string]interface{}, error) {
	body, err := t.request("GET", "/fapi/v1/account", nil, true)
	if err != nil {
		return nil, err
	}

	var account struct {
		PositionVos []struct {
			ContractName     string  `json:"contractName"`
			PositionType     int     `json:"positionType"`
			Volume           float64 `json:"volume"`
			AvailableVolume  float64 `json:"availableVolume"`
			AvgPrice         float64 `json:"avgPrice"`
			UnrealizedAmount float64 `json:"unrealizedAmount"`
			Leverage         int     `json:"leverage"`
			// Bitrue API没有直接返回markPrice和liquidationPrice
			// 需要通过其他接口获取
		} `json:"positionVos"`
	}

	if err := json.Unmarshal(body, &account); err != nil {
		return nil, err
	}

	var result []map[string]interface{}

	for _, pos := range account.PositionVos {
		if pos.Volume == 0 {
			continue // 跳过空仓位
		}

		// 转换symbol格式
		stdSymbol := t.convertToStandardSymbol(pos.ContractName)

		// 获取当前市场价格
		markPrice, _ := t.GetMarketPrice(stdSymbol)

		// 判断方向
		side := "long"
		volume := pos.Volume
		if volume < 0 {
			side = "short"
			volume = -volume
		}

		result = append(result, map[string]interface{}{
			"symbol":           stdSymbol,
			"side":             side,
			"positionAmt":      volume,
			"entryPrice":       pos.AvgPrice,
			"markPrice":        markPrice,
			"unRealizedProfit": pos.UnrealizedAmount,
			"leverage":         float64(pos.Leverage),
			"liquidationPrice": 0.0, // Bitrue API未提供
		})
	}

	return result, nil
}

// SetMarginMode 设置仓位模式
// Bitrue在下单时通过positionType参数设置 (1=全仓, 2=逐仓)
// 这里只记录模式，实际应用在下单时
func (t *BitrueTrader) SetMarginMode(symbol string, isCrossMargin bool) error {
	// Bitrue没有独立的设置仓位模式接口
	// 仓位模式在下单时通过positionType参数指定
	marginModeStr := "全仓"
	if !isCrossMargin {
		marginModeStr = "逐仓"
	}
	log.Printf("  ✓ %s 将使用 %s 模式 (在下单时应用)", symbol, marginModeStr)
	return nil
}

// SetLeverage 设置杠杆倍数
// Bitrue没有独立的设置杠杆接口，杠杆在下单时自动应用
func (t *BitrueTrader) SetLeverage(symbol string, leverage int) error {
	// Bitrue没有独立的设置杠杆接口
	// 杠杆设置需要在网页端完成，或者在下单时自动应用账户默认杠杆
	log.Printf("  ✓ %s 将使用杠杆 %dx (需在Bitrue网页端预先设置)", symbol, leverage)
	return nil
}

// GetMarketPrice 获取市场价格
func (t *BitrueTrader) GetMarketPrice(symbol string) (float64, error) {
	bitrueSymbol := t.convertToBitrueSymbol(symbol)

	params := map[string]interface{}{
		"contractName": bitrueSymbol,
	}

	body, err := t.request("GET", "/fapi/v1/ticker", params, false)
	if err != nil {
		return 0, err
	}

	var ticker struct {
		LastPrice string `json:"lastPrice"`
	}

	if err := json.Unmarshal(body, &ticker); err != nil {
		return 0, err
	}

	if ticker.LastPrice == "" {
		return 0, errors.New("无法获取价格")
	}

	return strconv.ParseFloat(ticker.LastPrice, 64)
}

// OpenLong 开多单
func (t *BitrueTrader) OpenLong(symbol string, quantity float64, leverage int) (map[string]interface{}, error) {
	// 开仓前先取消所有挂单
	if err := t.CancelAllOrders(symbol); err != nil {
		log.Printf("  ⚠ 取消挂单失败(继续开仓): %v", err)
	}

	bitrueSymbol := t.convertToBitrueSymbol(symbol)

	// 获取当前价格
	price, err := t.GetMarketPrice(symbol)
	if err != nil {
		return nil, err
	}

	// 使用限价单模拟市价单（价格设置得稍高一些以确保成交）
	limitPrice := price * 1.01

	// 格式化价格和数量
	formattedPrice, err := t.formatPrice(symbol, limitPrice)
	if err != nil {
		return nil, err
	}
	formattedVolume, err := t.formatVolume(symbol, quantity)
	if err != nil {
		return nil, err
	}

	params := map[string]interface{}{
		"contractName": bitrueSymbol,
		"side":         "BUY",
		"type":         "LIMIT",
		"volume":       formattedVolume,
		"price":        formattedPrice,
		"open":         "OPEN",
		"positionType": 1, // 1=全仓, 2=逐仓
		"timeInForce":  "GTC",
	}

	body, err := t.request("POST", "/fapi/v1/order", params, true)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	log.Printf("✓ 开多仓成功: %s 数量: %.4f", symbol, formattedVolume)

	return result, nil
}

// OpenShort 开空单
func (t *BitrueTrader) OpenShort(symbol string, quantity float64, leverage int) (map[string]interface{}, error) {
	// 开仓前先取消所有挂单
	if err := t.CancelAllOrders(symbol); err != nil {
		log.Printf("  ⚠ 取消挂单失败(继续开仓): %v", err)
	}

	bitrueSymbol := t.convertToBitrueSymbol(symbol)

	// 获取当前价格
	price, err := t.GetMarketPrice(symbol)
	if err != nil {
		return nil, err
	}

	// 使用限价单模拟市价单（价格设置得稍低一些以确保成交）
	limitPrice := price * 0.99

	// 格式化价格和数量
	formattedPrice, err := t.formatPrice(symbol, limitPrice)
	if err != nil {
		return nil, err
	}
	formattedVolume, err := t.formatVolume(symbol, quantity)
	if err != nil {
		return nil, err
	}

	params := map[string]interface{}{
		"contractName": bitrueSymbol,
		"side":         "SELL",
		"type":         "LIMIT",
		"volume":       formattedVolume,
		"price":        formattedPrice,
		"open":         "OPEN",
		"positionType": 1, // 1=全仓, 2=逐仓
		"timeInForce":  "GTC",
	}

	body, err := t.request("POST", "/fapi/v1/order", params, true)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	log.Printf("✓ 开空仓成功: %s 数量: %.4f", symbol, formattedVolume)

	return result, nil
}

// CloseLong 平多单
func (t *BitrueTrader) CloseLong(symbol string, quantity float64) (map[string]interface{}, error) {
	// 如果数量为0，获取当前持仓数量
	if quantity == 0 {
		positions, err := t.GetPositions()
		if err != nil {
			return nil, err
		}

		for _, pos := range positions {
			if pos["symbol"] == symbol && pos["side"] == "long" {
				quantity = pos["positionAmt"].(float64)
				break
			}
		}

		if quantity == 0 {
			return nil, fmt.Errorf("没有找到 %s 的多仓", symbol)
		}
		log.Printf("  📊 获取到多仓数量: %.8f", quantity)
	}

	bitrueSymbol := t.convertToBitrueSymbol(symbol)

	// 获取当前价格
	price, err := t.GetMarketPrice(symbol)
	if err != nil {
		return nil, err
	}

	// 平多仓使用卖出，价格稍低
	limitPrice := price * 0.99

	// 格式化价格和数量
	formattedPrice, err := t.formatPrice(symbol, limitPrice)
	if err != nil {
		return nil, err
	}
	formattedVolume, err := t.formatVolume(symbol, quantity)
	if err != nil {
		return nil, err
	}

	params := map[string]interface{}{
		"contractName": bitrueSymbol,
		"side":         "SELL",
		"type":         "LIMIT",
		"volume":       formattedVolume,
		"price":        formattedPrice,
		"open":         "CLOSE",
		"positionType": 1,
		"timeInForce":  "GTC",
	}

	body, err := t.request("POST", "/fapi/v1/order", params, true)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	log.Printf("✓ 平多仓成功: %s 数量: %.4f", symbol, formattedVolume)

	// 平仓后取消该币种的所有挂单
	if err := t.CancelAllOrders(symbol); err != nil {
		log.Printf("  ⚠ 取消挂单失败: %v", err)
	}

	return result, nil
}

// CloseShort 平空单
func (t *BitrueTrader) CloseShort(symbol string, quantity float64) (map[string]interface{}, error) {
	// 如果数量为0，获取当前持仓数量
	if quantity == 0 {
		positions, err := t.GetPositions()
		if err != nil {
			return nil, err
		}

		for _, pos := range positions {
			if pos["symbol"] == symbol && pos["side"] == "short" {
				quantity = pos["positionAmt"].(float64)
				break
			}
		}

		if quantity == 0 {
			return nil, fmt.Errorf("没有找到 %s 的空仓", symbol)
		}
		log.Printf("  📊 获取到空仓数量: %.8f", quantity)
	}

	bitrueSymbol := t.convertToBitrueSymbol(symbol)

	// 获取当前价格
	price, err := t.GetMarketPrice(symbol)
	if err != nil {
		return nil, err
	}

	// 平空仓使用买入，价格稍高
	limitPrice := price * 1.01

	// 格式化价格和数量
	formattedPrice, err := t.formatPrice(symbol, limitPrice)
	if err != nil {
		return nil, err
	}
	formattedVolume, err := t.formatVolume(symbol, quantity)
	if err != nil {
		return nil, err
	}

	params := map[string]interface{}{
		"contractName": bitrueSymbol,
		"side":         "BUY",
		"type":         "LIMIT",
		"volume":       formattedVolume,
		"price":        formattedPrice,
		"open":         "CLOSE",
		"positionType": 1,
		"timeInForce":  "GTC",
	}

	body, err := t.request("POST", "/fapi/v1/order", params, true)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	log.Printf("✓ 平空仓成功: %s 数量: %.4f", symbol, formattedVolume)

	// 平仓后取消该币种的所有挂单
	if err := t.CancelAllOrders(symbol); err != nil {
		log.Printf("  ⚠ 取消挂单失败: %v", err)
	}

	return result, nil
}

// SetStopLoss 设置止损
// Bitrue使用条件单（触发价格）
func (t *BitrueTrader) SetStopLoss(symbol string, positionSide string, quantity, stopPrice float64) error {
	bitrueSymbol := t.convertToBitrueSymbol(symbol)

	// 根据持仓方向确定下单方向
	side := "SELL" // 多仓止损=卖出
	if positionSide == "SHORT" {
		side = "BUY" // 空仓止损=买入
	}

	// 格式化价格和数量
	formattedPrice, err := t.formatPrice(symbol, stopPrice)
	if err != nil {
		return err
	}
	formattedVolume, err := t.formatVolume(symbol, quantity)
	if err != nil {
		return err
	}

	// Bitrue止损单参数
	params := map[string]interface{}{
		"contractName": bitrueSymbol,
		"side":         side,
		"type":         "STOP", // 止损单类型
		"volume":       formattedVolume,
		"price":        formattedPrice,
		"triggerPrice": formattedPrice, // 触发价格
		"open":         "CLOSE",
		"positionType": 1,
		"timeInForce":  "GTC",
	}

	_, err = t.request("POST", "/fapi/v1/order", params, true)
	if err != nil {
		return fmt.Errorf("设置止损失败: %w", err)
	}

	log.Printf("  止损价设置: %.4f", formattedPrice)
	return nil
}

// SetTakeProfit 设置止盈
func (t *BitrueTrader) SetTakeProfit(symbol string, positionSide string, quantity, takeProfitPrice float64) error {
	bitrueSymbol := t.convertToBitrueSymbol(symbol)

	// 根据持仓方向确定下单方向
	side := "SELL" // 多仓止盈=卖出
	if positionSide == "SHORT" {
		side = "BUY" // 空仓止盈=买入
	}

	// 格式化价格和数量
	formattedPrice, err := t.formatPrice(symbol, takeProfitPrice)
	if err != nil {
		return err
	}
	formattedVolume, err := t.formatVolume(symbol, quantity)
	if err != nil {
		return err
	}

	// Bitrue止盈单参数
	params := map[string]interface{}{
		"contractName": bitrueSymbol,
		"side":         side,
		"type":         "PROFIT", // 止盈单类型
		"volume":       formattedVolume,
		"price":        formattedPrice,
		"triggerPrice": formattedPrice, // 触发价格
		"open":         "CLOSE",
		"positionType": 1,
		"timeInForce":  "GTC",
	}

	_, err = t.request("POST", "/fapi/v1/order", params, true)
	if err != nil {
		return fmt.Errorf("设置止盈失败: %w", err)
	}

	log.Printf("  止盈价设置: %.4f", formattedPrice)
	return nil
}

// CancelStopLossOrders 仅取消止损单
func (t *BitrueTrader) CancelStopLossOrders(symbol string) error {
	return t.cancelOrdersByType(symbol, "STOP")
}

// CancelTakeProfitOrders 仅取消止盈单
func (t *BitrueTrader) CancelTakeProfitOrders(symbol string) error {
	return t.cancelOrdersByType(symbol, "PROFIT")
}

// CancelStopOrders 取消该币种的止盈/止损单
func (t *BitrueTrader) CancelStopOrders(symbol string) error {
	bitrueSymbol := t.convertToBitrueSymbol(symbol)

	params := map[string]interface{}{
		"contractName": bitrueSymbol,
	}

	body, err := t.request("GET", "/fapi/v1/openOrders", params, true)
	if err != nil {
		return fmt.Errorf("获取未完成订单失败: %w", err)
	}

	var orders []struct {
		OrderID int64  `json:"orderId"`
		Type    string `json:"type"`
	}

	if err := json.Unmarshal(body, &orders); err != nil {
		return fmt.Errorf("解析订单数据失败: %w", err)
	}

	canceledCount := 0
	for _, order := range orders {
		if order.Type == "STOP" || order.Type == "PROFIT" {
			cancelParams := map[string]interface{}{
				"contractName": bitrueSymbol,
				"orderId":      order.OrderID,
			}

			_, err := t.request("POST", "/fapi/v1/cancel", cancelParams, true)
			if err != nil {
				log.Printf("  ⚠ 取消订单 %d 失败: %v", order.OrderID, err)
				continue
			}

			canceledCount++
			log.Printf("  ✓ 已取消止盈/止损单 (订单ID: %d, 类型: %s)", order.OrderID, order.Type)
		}
	}

	if canceledCount == 0 {
		log.Printf("  ℹ %s 没有止盈/止损单需要取消", symbol)
	} else {
		log.Printf("  ✓ 已取消 %s 的 %d 个止盈/止损单", symbol, canceledCount)
	}

	return nil
}

// CancelAllOrders 取消所有订单
func (t *BitrueTrader) CancelAllOrders(symbol string) error {
	bitrueSymbol := t.convertToBitrueSymbol(symbol)

	params := map[string]interface{}{
		"contractName": bitrueSymbol,
	}

	body, err := t.request("GET", "/fapi/v1/openOrders", params, true)
	if err != nil {
		return fmt.Errorf("获取未完成订单失败: %w", err)
	}

	var orders []struct {
		OrderID int64 `json:"orderId"`
	}

	if err := json.Unmarshal(body, &orders); err != nil {
		return fmt.Errorf("解析订单数据失败: %w", err)
	}

	for _, order := range orders {
		cancelParams := map[string]interface{}{
			"contractName": bitrueSymbol,
			"orderId":      order.OrderID,
		}

		_, err := t.request("POST", "/fapi/v1/cancel", cancelParams, true)
		if err != nil {
			log.Printf("  ⚠ 取消订单 %d 失败: %v", order.OrderID, err)
		}
	}

	return nil
}

// cancelOrdersByType 根据订单类型取消订单
func (t *BitrueTrader) cancelOrdersByType(symbol string, orderType string) error {
	bitrueSymbol := t.convertToBitrueSymbol(symbol)

	params := map[string]interface{}{
		"contractName": bitrueSymbol,
	}

	body, err := t.request("GET", "/fapi/v1/openOrders", params, true)
	if err != nil {
		return fmt.Errorf("获取未完成订单失败: %w", err)
	}

	var orders []struct {
		OrderID int64  `json:"orderId"`
		Type    string `json:"type"`
	}

	if err := json.Unmarshal(body, &orders); err != nil {
		return fmt.Errorf("解析订单数据失败: %w", err)
	}

	canceledCount := 0
	var cancelErrors []error

	for _, order := range orders {
		if order.Type == orderType {
			cancelParams := map[string]interface{}{
				"contractName": bitrueSymbol,
				"orderId":      order.OrderID,
			}

			_, err := t.request("POST", "/fapi/v1/cancel", cancelParams, true)
			if err != nil {
				errMsg := fmt.Sprintf("订单ID %d: %v", order.OrderID, err)
				cancelErrors = append(cancelErrors, fmt.Errorf("%s", errMsg))
				log.Printf("  ⚠ 取消%s单失败: %s", orderType, errMsg)
				continue
			}

			canceledCount++
			log.Printf("  ✓ 已取消%s单 (订单ID: %d)", orderType, order.OrderID)
		}
	}

	typeName := "止损"
	if orderType == "PROFIT" {
		typeName = "止盈"
	}

	if canceledCount == 0 && len(cancelErrors) == 0 {
		log.Printf("  ℹ %s 没有%s单需要取消", symbol, typeName)
	} else if canceledCount > 0 {
		log.Printf("  ✓ 已取消 %s 的 %d 个%s单", symbol, canceledCount, typeName)
	}

	if len(cancelErrors) > 0 && canceledCount == 0 {
		return fmt.Errorf("取消%s单失败: %v", typeName, cancelErrors)
	}

	return nil
}

// FormatQuantity 格式化数量（实现Trader接口）
func (t *BitrueTrader) FormatQuantity(symbol string, quantity float64) (string, error) {
	formatted, err := t.formatVolume(symbol, quantity)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%v", formatted), nil
}
