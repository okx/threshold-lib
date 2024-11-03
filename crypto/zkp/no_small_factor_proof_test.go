package zkp

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/okx/threshold-lib/crypto/pedersen"
	"github.com/stretchr/testify/require"
)

const (
	pedParamsStr = "{\"S\":13817395213773423665748976106069887563215400031989903034408049429189159623246888881612592317674727022888953512054385819429092977115403239906258157202244097241485415363298451415160695747089414269924804324563172126254731208935288395176853289248153163224344837947195551794352714372170241862006229745350720206100529568569903326706522465071953160407559249327843406829943397877417499624472421566341035438108378118335635756026876702727809585543003644182652106484868612447592410485489825417344886519578261106535281338786314136945870688227272056742451068061150072357667594255200825455371193294242284424803170897668949426555425,\"T\":12646452867496863933920518693245448076945324934065007179150675937842809462143388041137327217366863480604024164454053181476261134056508042173677396619091621046697295845899271429173694327241538528083559862042799634332752900457929032597135516603322969801330022552710943053979389903574351073197184678971851077867038477328389498837083801534992728001111781813986801825092859612842444546665472308805440478879962403831545378204083199782379489048179968109465785715883325834618148037339660146296886384179431949544922529706581349706257973164686615951349082129935811005980537931685280584875211268792796177935510214118753649879253,\"Ntilde\":31203981932332851330684971902204167683279436670222650769704368232932597705714815213178259489761831567249732027535018308556325009159384987976366013997949424098969119874421206142006896077007148702247620090092698015141805616903301830015820714685345412225561073461417430194324516227295135698439299870481751523667676431358649281499087889608995507141224753283985619068058187485838992611877407102364133884863015657088284949501806199503611081229593950592540379747602331347045247394118938229140216860250432071881042897379699134249065339561622661666095475238856269226548968314840715169536541404692806522202600968606674667098881}"

	b1024_p = "135751741531138630212986367401440473273345553443240206900599775398484086842888950218156388524736127269745656746518539943387683515618105506449152508681861203638152551542315779705218077005283211144957273561287947835140306529354946028765560671699915629581808024606780437002804746279589409788279591036567260847227"
	b1024_q = "151458285289404559095250126289760184902419973267369170722482301171598360112355719472305547333766906244597020958615595692184779784507175332692351841265396728266455511450890511628195030937409161107049709530893185554561921286449431744046314846346879202144102087443741839967497005583531004939068822503717575212319"

	b768_p = "1325839231743416374620686712133403827043315993329289175885986963297122960181833548942952142840880271206395287902965177900015056139702734301052174127938466019292527958710838233025280102212470812534593950553337147566919324954468898459"

	b1280_q = "18327524347413690449127238110545259210224771561930270348310035986595096421362933423378702131886290683683168961074755221055465737807332488323226307034387744539799245862320786361206743128766447425053744325626728682651323218316207819235700824614409586830386172362806011443980931285310551055790394689269760847114946454751822594894135344913744101994440920653246469863123202747145482654099423"
)

func TestNoSmallFactorCompleteness(t *testing.T) {
	ped := &pedersen.PedersenParameters{}
	err := json.Unmarshal([]byte(pedParamsStr), ped)
	require.NoError(t, err)
	p, succ := new(big.Int).SetString(b1024_p, 10)
	require.True(t, succ)
	q, succ := new(big.Int).SetString(b1024_q, 10)
	require.True(t, succ)
	n := new(big.Int).Mul(p, q)

	var l uint = 16
	proof := NoSmallFactorProve(n, p, q, l, ped, &SecurityParameter{
		Q_bitlen: 64,
		Epsilon:  128,
	})
	r := NoSmallFactorVerify(n, proof, ped)
	require.True(t, r)
}

func TestNoSmallFactorSoundness(t *testing.T) {
	ped := &pedersen.PedersenParameters{}
	err := json.Unmarshal([]byte(pedParamsStr), ped)
	require.NoError(t, err)

	t.Run("small factor should fail. ", func(t *testing.T) {
		p, succ := new(big.Int).SetString(b768_p, 10)
		require.True(t, succ)
		q, succ := new(big.Int).SetString(b1280_q, 10)
		require.True(t, succ)
		n := new(big.Int).Mul(p, q)

		var l uint = 16
		proof := NoSmallFactorProve(n, p, q, l, ped, &SecurityParameter{
			Q_bitlen: 64,
			Epsilon:  128,
		})
		r := NoSmallFactorVerify(n, proof, ped)
		require.False(t, r)
	})

	t.Run("wrong factor should fail. ", func(t *testing.T) {
		p, succ := new(big.Int).SetString(b768_p, 10)
		require.True(t, succ)
		q, succ := new(big.Int).SetString(b1280_q, 10)
		require.True(t, succ)
		n := new(big.Int).Mul(p, q)
		n = new(big.Int).Add(n, new(big.Int).SetInt64(10))

		var l uint = 16
		proof := NoSmallFactorProve(n, p, q, l, ped, &SecurityParameter{
			Q_bitlen: 64,
			Epsilon:  128,
		})
		r := NoSmallFactorVerify(n, proof, ped)
		require.False(t, r)
	})
}
