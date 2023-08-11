package paillier

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"math/big"
)

const ZK_PAILLIER_alpha = 6370
const ZK_PAILLIER_m2 = 11

// product of all primes < alpha
const PrimeStr = "44871651744009136248115543081640547413785854417842050160655833875792914833852769205831424979368719986889519256934239452438251108738670217298542180982547421007901019408155961940142468907900676141149633188172029947498666222471142795699128314649438784106402197023949268047384343715946006767671319388463922366703585708460135453240679421061304864609915827908896062350138633849514905858373339528086006145373712431756746905467935232935398951226852071323775412278763371089401544920873813490290672436809231516731065356763193493525160238868779310055137922174496115680527519932793977258424479253973670103634070028863591207614649216492780891961054287421831028229266989697058385612003557825398202548657910983931484180193293615175594925895929359108723671212631368891689462486968022029482413912928883488902454913524492340322599922718890878760895105937402913873414377276608236656947832307175090505396675623505955607363683869194683635689701238311577953994900734498406703176954324494694474545570839360607926610248093452739817614097197031607820417729009847465138388398887861935127785385309564525648905444610640901769290645369888935446477559073843982605496992468605588284307311971153579731703863970674466666844817336319390617551354845025116350295041840093627836067370100384861820888752358520276041000456608056339377573485917445104757987800101659688183150320442308091835974182809184299472568260682774683272697993855730500061223160274918361373258473553412704497335663924406111413972911417644029226449602417135116011968946232623154008710271296183350215563946003547561056456285939676838623311370087238225630994506113422922846572616538637723054222166159389475617214681282874373185283568512603887750846072033376432252677883915884203823739988948315257311383912016966925295975180180438969999175030785077627458887411146486902613291202008193902979800279637509789564807502239686755727063367075758492823731724669702442450502667810890608807091448688985203084972035197770874223259420649055450382725355162738490355628688943706634905982449810389530661328557381850782677221561924983234877936783136471890539395124220965982831778882400224156689487137227198030461624542872774217771594215907203725682315714199249588874271661233929713660269883273404764648327455796699366900022345171030564747210542398285078804310752063852249740561571105640741618793118627170070315410588646442647771802031066589341358879304845579387079972404386434238273904239604603511925708377008467129590636257287965232576327580009018475271364237665836186806027331208426256451429549641988386585949300254487647395222785274120561299318070944530096970076560461229486504018773252771360855091191876004370694539453020462096690084476681253865429278552786361828508910022714749051734108364178374765700925133405508684883070"

func NIZKProofWithSession(N, phiN *big.Int, sessionID []byte) ([]byte, error) {
	NLen := (N.BitLen() + 7) / 8
	out := make([]byte, NLen * ZK_PAILLIER_m2)

	NInv := new(big.Int).ModInverse(N, phiN)
	seed := sha256.Sum256(append(N.Bytes(), sessionID...))

	// Create a new AES-CTR cipher instance
	block, err := aes.NewCipher(seed[:16]) // Use the first 16 bytes of seed
	if err != nil {
		return nil, err
	}

	// Create a buffer for encrypted data
	encLen := NLen/16 + 2
	enc := make([]byte, encLen * 16) // AES block size is 16 bytes

	offset := 0
	for i := 0; i < ZK_PAILLIER_m2; i++ {
		// Clear the encryption buffer
		copy(enc, make([]byte, encLen*16))

		// Update the counter mode with the encryption buffer
		ctr := cipher.NewCTR(block, make([]byte, 16))
		ctr.XORKeyStream(enc, enc)

		// Convert the encrypted buffer to a big integer
		encBigInt := new(big.Int).SetBytes(enc)

		// Apply modulo N operation to the encrypted value
		rho := new(big.Int).Mod(encBigInt, N)

		// Compute sigma using modular exponentiation
		sigma := new(big.Int).Exp(rho, NInv, N)

		// Convert the result back to bytes and place it in the output buffer
		sigmaBytes := sigma.Bytes()
		copy(out[offset:], padBytes(sigmaBytes, NLen))

		offset += NLen
	}

	return out, nil
}

func NIZKVerifyWithSession(N *big.Int, pi, sessionID []byte) bool {
	// Early test for small primes
	primeProduct, ok := new(big.Int).SetString(PrimeStr, 10)
	if !ok {
		return false
	}
	if new(big.Int).Mod(N, primeProduct).Sign() == 0 {
		return false
	}

	// Byte length test
	NLen := (N.BitLen() + 7) / 8
	if len(pi) != NLen * ZK_PAILLIER_m2 {
		return false
	}

	seed := sha256.Sum256(append(N.Bytes(), sessionID...))

	block, err := aes.NewCipher(seed[:16])
	if err != nil {
		return false
	}

	encLen := (NLen/16) + 2
	enc := make([]byte, encLen * 16)

	offset := 0
	for i := 0; i < ZK_PAILLIER_m2; i++ {
		copy(enc, make([]byte, encLen * 16))

		ctr := cipher.NewCTR(block, make([]byte, 16))
		ctr.XORKeyStream(enc, enc)

		encBigInt := new(big.Int).SetBytes(enc)
		rho := new(big.Int).Mod(encBigInt, N)

		sigma := new(big.Int).SetBytes(pi[offset : offset+NLen])
		sigmaModN := new(big.Int).Exp(sigma, N, N)

		if rho.Cmp(sigmaModN) != 0 {
			return false
		}

		offset += NLen
	}

	return true
}

func padBytes(src []byte, length int) []byte {
	if len(src) >= length {
		return src
	}
	padding := make([]byte, length-len(src))
	return append(padding, src...)
}
